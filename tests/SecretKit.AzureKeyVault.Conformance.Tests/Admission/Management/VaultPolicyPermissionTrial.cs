using System.Diagnostics.CodeAnalysis;
using System.Globalization;
using System.Security.Cryptography;
using System.Text;
using System.Text.Json;
using System.Text.Json.Serialization;
using Azure;
using Azure.Core;
using Azure.Core.Pipeline;
using Azure.Security.KeyVault.Secrets;
using SecretKit.AzureKeyVault.Management;
using SecretKit.Core;
using M = SecretKit.AzureKeyVault.Conformance.Tests.Admission.Management.VaultAdministrationCollector;

namespace SecretKit.AzureKeyVault.Conformance.Tests.Admission.Management;

// Host preparation contract, not provisioning or a policy-effect projection:
// - Before Arm, the host journals the owned vault and each dedicated secret
//   under the ORIGINAL selector/owner/lease. Every secret must have an owned
//   creation history, even when its independently prepared state is now Absent.
// - Active/Deleted/Absent are explicit host preparation assertions. The journal
//   proves local ownership, not remote state. Unknown is never trial-ready.
// - A restore artifact must be the native opaque backup of that exact owned
//   target, prepared by the host before deletion/purge. Its contents cannot be
//   inspected here to prove provenance; arbitrary user/reply backups are outside
//   this contract. Returned IDs validate the fixed target, never select one.
//
// One shared journal root is deliberate. Immutable read fixtures may be shared;
// mutation targets stay dedicated. Each source declares at most twenty-two
// distinct fixture and inventory names. Missing trials and trials after uncertainty
// remain Unavailable. SDK completion alone never settles a mutation.
// This source NEVER polls, settles, cleans up, replays, or changes access policy.
internal sealed class VaultPolicyPermissionTrial : IAsyncDisposable
{
    internal const string Revision = "2025-07-01";
    internal const string Audience = "https://vault.azure.net/.default";
    internal enum PreparedState { Unknown, Active, Deleted, Absent }
    internal enum Failure { None, Unprepared, Boundary, Unavailable, Deadline }
    internal sealed record PrincipalClaim([property: JsonIgnore] Guid TenantId,
        [property: JsonIgnore] Guid PrincipalId, [property: JsonIgnore] Guid? ApplicationId)
    {
        public override string ToString() => "[PolicyPrincipalClaim]";
    }
    internal sealed record Authority([property: JsonIgnore] string Label,
        [property: JsonIgnore] TokenCredential Credential, [property: JsonIgnore] HttpPipelineTransport Transport)
    {
        public override string ToString() => "[PolicyTrialAuthority]";
    }
    internal sealed record Limits(int MaximumResponseBytes, int MaximumMaterialBytes, int MaximumBackupBytes,
        int MaximumNodes, int MaximumRows, int MaximumDepth, TimeSpan Timeout);
    internal sealed record PreparedFixture([property: JsonIgnore] SecretPermission Permission,
        [property: JsonIgnore] bool DeniedAuthority, [property: JsonIgnore] string Name,
        [property: JsonIgnore] string? Version, [property: JsonIgnore] PreparedState State,
        [property: JsonIgnore] string? Sha256, [property: JsonIgnore] SecretMaterial? OwnedSet,
        [property: JsonIgnore] AzureSecretBackup? Backup)
    {
        public override string ToString() => "[PreparedPermissionFixture]";
    }
    internal sealed record Manifest([property: JsonIgnore] string Owner,
        [property: JsonIgnore] M.Binding Original, [property: JsonIgnore] string ApiRevision,
        [property: JsonIgnore] PreparedFixture[] Fixtures,
        [property: JsonIgnore] string[]? InventoryOnly = null)
    {
        public override string ToString() => "[PreparedPermissionManifest]";
    }
    internal sealed class Window(M.Binding binding, DateTimeOffset armedAt)
    {
        internal M.Binding Binding { get; } = binding;
        internal DateTimeOffset ArmedAt { get; } = armedAt;
        internal Guid Id { get; } = Guid.NewGuid();
        public override string ToString() => "[PolicyPermissionWindow]";
    }
    internal sealed class Observation
    {
        internal required SecretPermission Permission { get; init; }
        internal required bool DeniedAuthority { get; init; }
        internal required string Identity { get; init; }
        internal required SecretStatus Status { get; init; }
        internal required Failure Failure { get; init; }
        internal bool Attempted { get; init; }
        internal bool Accepted { get; init; }
        internal bool SdkSucceeded { get; init; }
        internal bool RemoteSettled { get; init; }
        internal string? NativeRequestId { get; init; }
        // Exactly the installed SDK's operation ID (which can be NOT_SET).
        // This is evidence only, never a URL/delegate used for another send.
        internal string? NativeHandle { get; init; }
        internal string? SettlementRequestId { get; init; }
        internal Failure SettlementFailure { get; init; }
        public override string ToString() => "[PolicyPermissionObservation]";
    }
    internal sealed class Measurement
    {
        internal required M.Binding Binding { get; init; }
        internal required PrincipalClaim IntendedPrincipal { get; init; }
        internal required Guid WindowId { get; init; }
        internal required DateTimeOffset ArmedAt { get; init; }
        internal required DateTimeOffset FinishedAt { get; init; }
        internal required IReadOnlyList<Observation> Observations { get; init; }
        internal string ApiRevision => Revision;
        internal bool PrincipalQualified => false;
        internal bool EgressQualified => false;
        public override string ToString() => "[PolicyPermissionMeasurement]";
    }

    private sealed class OwnedFixture(PreparedFixture fixture) : IDisposable
    {
        // The record contains no material after snapshotting.
        internal PreparedFixture Fixture { get; } = fixture with { OwnedSet = null, Backup = null };
        internal char[]? Set;
        internal byte[]? Backup;
        public void Dispose()
        {
            if (Set is not null) Array.Clear(Set);
            if (Backup is not null) CryptographicOperations.ZeroMemory(Backup);
        }
    }
    private sealed class Registration(string owner, long timestamp, OwnedFixture[] fixtures, string[] inventoryOnly)
    {
        internal string Owner { get; } = owner;
        internal long Timestamp { get; } = timestamp;
        internal OwnedFixture[] Fixtures { get; } = fixtures;
        internal string[] InventoryOnly { get; } = inventoryOnly;
        internal bool Consumed;
        internal Measurement? Sealed;
        internal readonly TaskCompletionSource Drained = new(TaskCreationOptions.RunContinuationsAsynchronously);
        internal void Release()
        {
            foreach (var fixture in Fixtures) fixture.Dispose();
            Drained.TrySetResult();
        }
    }
    private readonly RoleFixtureJournal journal;
    private readonly PrincipalClaim intendedPrincipal;
    private readonly Authority intended, denied;
    private readonly Authority? settlementObserver;
    private readonly Limits limits;
    private readonly TimeProvider time;
    private readonly object gate = new();
    private readonly Dictionary<Window, Registration> windows = [];
    private readonly HashSet<Guid> nonces = [], leases = [];
    private readonly CancellationTokenSource stop = new();
    private TaskCompletionSource? disposal;
    private bool closed;

    internal VaultPolicyPermissionTrial(RoleFixtureJournal journal, PrincipalClaim intendedPrincipal,
        Authority intended, Authority denied, Limits limits, TimeProvider time, Authority? settlementObserver = null)
    {
        if (journal is null || intendedPrincipal is null || intendedPrincipal.TenantId == Guid.Empty ||
            intendedPrincipal.PrincipalId == Guid.Empty || intendedPrincipal.ApplicationId == Guid.Empty ||
            !Valid(intended) || !Valid(denied) || settlementObserver is not null && !Valid(settlementObserver) ||
            limits is null || time is null ||
            limits.MaximumResponseBytes is < 1024 or > 1024 * 1024 ||
            limits.MaximumMaterialBytes is < 1 or > 16384 || limits.MaximumMaterialBytes > limits.MaximumResponseBytes ||
            limits.MaximumBackupBytes < 1 || limits.MaximumBackupBytes > limits.MaximumResponseBytes ||
            limits.MaximumNodes is < 8 or > 65536 || limits.MaximumRows is < 1 or > 128 ||
            limits.MaximumDepth is < 2 or > 32 || limits.Timeout <= TimeSpan.Zero || limits.Timeout > TimeSpan.FromMinutes(2))
            throw new ArgumentException("policy-trial-input");
        this.journal = journal;
        this.intendedPrincipal = intendedPrincipal;
        this.intended = intended;
        this.denied = denied;
        this.limits = limits;
        this.time = time;
        this.settlementObserver = settlementObserver;
    }

    internal Window Arm(Manifest manifest)
    {
        // Initializer and disposal share this lock. No partially initialized
        // protected snapshot can escape, or be cleared while still copying.
        lock (gate)
        {
            if (closed) throw new InvalidOperationException("policy-trial-window");
            var owned = new List<OwnedFixture>();
            try
            {
                Validate(manifest);
                if (windows.Count >= 32 || nonces.Contains(manifest.Original.Selector.Nonce) ||
                    leases.Contains(manifest.Original.LeaseId))
                    throw new InvalidOperationException("policy-trial-window");
                foreach (var fixture in manifest.Fixtures)
                {
                    var copy = new OwnedFixture(fixture);
                    owned.Add(copy);
                    if (fixture.OwnedSet is not null)
                    {
                        copy.Set = fixture.OwnedSet.ExportCharacters();
                        Require(copy.Set.Length is > 0 && copy.Set.Length <= limits.MaximumMaterialBytes);
                        byte[] utf8 = new UTF8Encoding(false, true).GetBytes(copy.Set);
                        try
                        {
                            Require(utf8.Length <= limits.MaximumMaterialBytes &&
                                Convert.ToHexString(SHA256.HashData(utf8)) == fixture.Sha256);
                        }
                        finally { CryptographicOperations.ZeroMemory(utf8); }
                    }
                    if (fixture.Backup is not null)
                    {
                        copy.Backup = fixture.Backup.Export();
                        Require(copy.Backup.Length > 0 && copy.Backup.Length <= limits.MaximumBackupBytes);
                    }
                }
                var armedAt = time.GetUtcNow();
                long timestamp = time.GetTimestamp();
                if (closed) throw new InvalidOperationException("policy-trial-window");
                var window = new Window(manifest.Original, armedAt);
                windows.Add(window, new(manifest.Owner, timestamp, owned.ToArray(),
                    manifest.InventoryOnly?.ToArray() ?? []));
                nonces.Add(manifest.Original.Selector.Nonce);
                leases.Add(manifest.Original.LeaseId);
                return window;
            }
            catch (Exception error)
            {
                foreach (var fixture in owned) fixture.Dispose();
                if (error is InvalidOperationException && error.Message == "policy-trial-window")
                    throw new InvalidOperationException("policy-trial-window");
                throw new ArgumentException("policy-trial-manifest");
            }
        }
    }

    internal async ValueTask<Measurement> CollectAsync(Window window, M.Binding binding,
        CancellationToken cancellationToken = default)
    {
        Registration registration;
        lock (gate)
        {
            if (closed || window is null || !windows.TryGetValue(window, out var found) ||
                found.Consumed || window.Binding != binding)
                throw new InvalidOperationException("policy-trial-window");
            registration = found;
            registration.Consumed = true;
        }
        var budget = new Budget(time, window.ArmedAt, registration.Timestamp, limits.Timeout);
        try
        {
            cancellationToken.ThrowIfCancellationRequested();
            using var deadline = new CancellationTokenSource(limits.Timeout, time);
            budget.Deadline = deadline;
            using var linked = CancellationTokenSource.CreateLinkedTokenSource(cancellationToken, deadline.Token, stop.Token);
            var observations = new List<Observation>();
            foreach (var permission in Enum.GetValues<SecretPermission>().OrderBy(Mutates))
            {
                // Denied-first is only sequencing, never a predicted status.
                // A surprising successful denied-authority mutation fences the
                // intended action just as any other uncertain mutation would.
                foreach (bool deniedAuthority in new[] { true, false })
                {
                    var fixture = registration.Fixtures.SingleOrDefault(f =>
                        f.Fixture.Permission == permission && f.Fixture.DeniedAuthority == deniedAuthority);
                    observations.Add(await TrialAsync(binding, registration, fixture, permission, deniedAuthority,
                        budget, linked.Token, cancellationToken).ConfigureAwait(false));
                }
            }
            cancellationToken.ThrowIfCancellationRequested();
            var result = new Measurement
            {
                Binding = binding,
                IntendedPrincipal = intendedPrincipal,
                WindowId = window.Id,
                ArmedAt = window.ArmedAt,
                FinishedAt = budget.ObservedAt,
                Observations = observations.AsReadOnly()
            };
            lock (gate) registration.Sealed = result;
            return result;
        }
        finally { registration.Release(); }
    }

    internal VaultAdministrationEffects.PolicyEffect[] ComposePolicyEffects(Window window, M.Binding binding,
        PrincipalClaim principal, Measurement measurement)
    {
        lock (gate)
        {
            Require(!closed && windows.TryGetValue(window, out var registration) &&
                registration.Consumed && registration.Drained.Task.IsCompleted &&
                ReferenceEquals(registration.Sealed, measurement) && window.Binding == binding &&
                measurement.Binding == binding && principal == intendedPrincipal);
            Require(measurement.Observations.Count == 16 &&
                measurement.Observations.Select(o => (o.Permission, o.DeniedAuthority)).Distinct().Count() == 16 &&
                measurement.Observations.All(o => Enum.IsDefined(o.Permission) && o.Attempted &&
                    o.Status is SecretStatus.Success or SecretStatus.Denied or SecretStatus.Absent &&
                    o.Failure == Failure.None && o.RemoteSettled && Text(o.NativeRequestId, 128)));
            return Enum.GetValues<SecretPermission>().Select(permission =>
            {
                var actual = measurement.Observations.Single(o => o.Permission == permission && !o.DeniedAuthority);
                var deniedActual = measurement.Observations.Single(o => o.Permission == permission && o.DeniedAuthority);
                return new VaultAdministrationEffects.PolicyEffect(intendedPrincipal.PrincipalId, permission,
                    actual.Status, deniedActual.Status, actual.NativeRequestId!);
            }).ToArray();
        }
    }

    private async Task<Observation> TrialAsync(M.Binding binding, Registration registration, OwnedFixture? owned,
        SecretPermission permission, bool deniedAuthority, Budget budget, CancellationToken token, CancellationToken caller)
    {
        var authority = deniedAuthority ? denied : intended;
        NativeTransport? boundary = null;
        bool sdkSucceeded = false, ended = true, remoteSettled = false;
        string? handle = null;
        Operation? operation = null;
        string? settlementRequestId = null;
        Failure settlementFailure = Failure.None;
        Failure failure = Failure.Unavailable;
        try
        {
            token.ThrowIfCancellationRequested();
            budget.Check();
            if (owned is null || !Ready(owned)) throw new Boundary(Failure.Unprepared);
            CheckOwnership(binding, registration, owned);
            var credential = new BoundCredential(authority.Credential, budget);
            boundary = new(this, authority, credential, binding, registration, owned, budget);
            var options = new SecretClientOptions(SecretClientOptions.ServiceVersion.V2025_07_01)
            {
                Transport = boundary,
                DisableChallengeResourceVerification = false
            };
            options.Retry.MaxRetries = 0;
            options.Diagnostics.IsLoggingEnabled = false;
            options.Diagnostics.IsLoggingContentEnabled = false;
            options.Diagnostics.IsDistributedTracingEnabled = false;
            var client = new SecretClient(Origin(binding), credential, options);
            // Retain and await the WHOLE task, including synchronous initializer,
            // native response/error parsing and any cancellation-ignoring borrower.
            Task<Operation?> actual = InvokeAsync(client, owned, binding, token);
            operation = await actual.ConfigureAwait(false);
            handle = operation?.Id;
            sdkSucceeded = true;
            token.ThrowIfCancellationRequested();
            budget.Check();
            Require(boundary.Valid);
            failure = Failure.None;
        }
        catch (Exception error)
        {
            failure = token.IsCancellationRequested ? Failure.Deadline :
                error is Boundary reason ? reason.Reason : Failure.Unavailable;
        }
        finally
        {
            if (boundary is not null)
            {
                try
                {
                    if (boundary.Dispatch != Guid.Empty)
                    {
                        // Valid rejection settles this attempt, NOT absence of
                        // any earlier mutation. No GET/404 can clear an old fence.
                        bool settled = !Mutates(permission) || boundary.Valid &&
                            (boundary.Status is 403 or 404 || sdkSucceeded &&
                                permission is SecretPermission.Set or SecretPermission.Restore or SecretPermission.Purge &&
                                boundary.Status == SuccessStatus(permission));
                        journal.EndDispatch(registration.Owner, binding.Selector, Resource(binding, owned!.Fixture.Name),
                            boundary.Dispatch, nativeSettled: settled);
                        remoteSettled = settled;
                        if (!settled && sdkSucceeded && operation is not null && settlementObserver is not null &&
                            boundary.Valid && boundary.Status == 200 && !token.IsCancellationRequested)
                        {
                            var statusBoundary = boundary.BeginStatus(settlementObserver);
                            bool statusSettled = false;
                            try
                            {
                                using var response = await operation.UpdateStatusAsync(token).ConfigureAwait(false);
                                token.ThrowIfCancellationRequested();
                                budget.Check();
                                Require(statusBoundary.Dispatch == boundary.Dispatch && statusBoundary.Valid &&
                                    statusBoundary.Status == 200 && operation.HasCompleted);
                                switch (operation)
                                {
                                    case DeleteSecretOperation deletion:
                                        ValidateProperties(deletion.Value.Properties, binding, owned.Fixture, exactVersion: true);
                                        break;
                                    case RecoverDeletedSecretOperation recovery:
                                        ValidateProperties(recovery.Value, binding, owned.Fixture, exactVersion: true);
                                        break;
                                    default: throw new Boundary();
                                }
                                statusSettled = true;
                                settlementRequestId = statusBoundary.RequestId;
                            }
                            catch (Exception error)
                            {
                                settlementFailure = token.IsCancellationRequested ? Failure.Deadline :
                                    error is Boundary reason ? reason.Reason : Failure.Unavailable;
                            }
                            finally
                            {
                                if (statusBoundary.Dispatch != Guid.Empty)
                                    journal.EndDispatch(registration.Owner, binding.Selector,
                                        Resource(binding, owned.Fixture.Name), statusBoundary.Dispatch, nativeSettled: statusSettled);
                            }
                            remoteSettled = statusSettled;
                        }
                    }
                }
                catch (Exception) { ended = false; failure = Failure.Unavailable; remoteSettled = false; }
                finally
                {
                    try { boundary.Dispose(); }
                    catch (Exception) { failure = Failure.Unavailable; sdkSucceeded = false; }
                }
            }
        }
        caller.ThrowIfCancellationRequested();
        bool available = false;
        if (!token.IsCancellationRequested && ended && boundary?.Valid == true)
        {
            try
            {
                budget.Check();
                available = boundary.Status is 403 or 404 ||
                    (sdkSucceeded && failure == Failure.None) || boundary.Status == 202;
            }
            catch (Exception) { failure = Failure.Deadline; }
        }
        caller.ThrowIfCancellationRequested();
        int status = boundary?.Status ?? 0;
        bool accepted = available && Mutates(permission) && status is >= 200 and < 300;
        return new()
        {
            Permission = permission,
            DeniedAuthority = deniedAuthority,
            Identity = authority.Label,
            Status = !available ? SecretStatus.Unavailable :
                status == 403 ? SecretStatus.Denied : status == 404 ? SecretStatus.Absent : SecretStatus.Success,
            Failure = available ? Failure.None : failure,
            Attempted = boundary is not null && boundary.Dispatch != Guid.Empty,
            Accepted = accepted,
            SdkSucceeded = sdkSucceeded,
            RemoteSettled = available && remoteSettled,
            NativeRequestId = boundary?.Valid == true ? boundary.RequestId : null,
            NativeHandle = handle,
            SettlementRequestId = settlementRequestId,
            SettlementFailure = settlementFailure
        };
    }

    private async Task<Operation?> InvokeAsync(SecretClient client, OwnedFixture owned, M.Binding binding, CancellationToken token)
    {
        var f = owned.Fixture;
        switch (f.Permission)
        {
            case SecretPermission.Get:
                var read = await client.GetSecretAsync(f.Name, f.Version, token).ConfigureAwait(false);
                ValidateProperties(read.Value.Properties, binding, f, exactVersion: true);
                Require(Hash(read.Value.Value) == f.Sha256);
                break;
            case SecretPermission.List:
                await using (var pages = client.GetPropertiesOfSecretsAsync(token).AsPages().GetAsyncEnumerator(token))
                {
                    Require(await pages.MoveNextAsync().ConfigureAwait(false));
                    Require(pages.Current.ContinuationToken is null && pages.Current.Values.Count <= limits.MaximumRows &&
                        pages.Current.Values.Any(p => p.Name == f.Name));
                }
                break;
            case SecretPermission.Set:
                var secret = new KeyVaultSecret(f.Name, new string(owned.Set!));
                secret.Properties.Enabled = true;
                var set = await client.SetSecretAsync(secret, token).ConfigureAwait(false);
                ValidateProperties(set.Value.Properties, binding, f, exactVersion: false);
                Require(Hash(set.Value.Value) == f.Sha256);
                break;
            case SecretPermission.Delete:
                var deletion = await client.StartDeleteSecretAsync(f.Name, token).ConfigureAwait(false);
                ValidateProperties(deletion.Value.Properties, binding, f, exactVersion: true);
                return deletion;
            case SecretPermission.Recover:
                var recovery = await client.StartRecoverDeletedSecretAsync(f.Name, token).ConfigureAwait(false);
                ValidateProperties(recovery.Value, binding, f, exactVersion: true);
                return recovery;
            case SecretPermission.Backup:
                byte[] bytes = (await client.BackupSecretAsync(f.Name, token).ConfigureAwait(false)).Value;
                try { Require(bytes.Length > 0 && bytes.Length <= limits.MaximumBackupBytes); }
                finally { CryptographicOperations.ZeroMemory(bytes); }
                break;
            case SecretPermission.Restore:
                var restored = await client.RestoreSecretBackupAsync(owned.Backup!, token).ConfigureAwait(false);
                ValidateProperties(restored.Value, binding, f, exactVersion: true);
                break;
            case SecretPermission.Purge:
                var purge = await client.PurgeDeletedSecretAsync(f.Name, token).ConfigureAwait(false);
                Require(purge.Status == 204);
                break;
            default: throw new Boundary();
        }
        return null;
    }

    private void CheckOwnership(M.Binding binding, Registration registration, OwnedFixture owned)
    {
        RoleFixtureJournal.Snapshot state;
        try { state = journal.Read(registration.Owner, binding.Selector); }
        catch (Exception) { throw new Boundary(Failure.Unprepared); }
        Require(state.LeaseId == binding.LeaseId && !state.Closing &&
            state.Resources.All(r => r.ActiveDispatch == Guid.Empty));
        var vault = state.Resources.SingleOrDefault(r => r.Id == VaultId(binding));
        var resource = state.Resources.SingleOrDefault(r => r.Id == Resource(binding, owned.Fixture.Name));
        Require(vault is { Borrowed: false, CreateAttempted: true, DeleteAttempted: false, Absent: false, CleanupOnly: false } &&
            resource is { Borrowed: false, CreateAttempted: true, DeleteAttempted: false, Absent: false, CleanupOnly: false, SelectedAttempted: false });
        // List may return any prepared coordinate, so every manifest member,
        // not just this action's target, must belong to the same owned root.
        foreach (var fixture in registration.Fixtures)
            Require(state.Resources.SingleOrDefault(r => r.Id == Resource(binding, fixture.Fixture.Name)) is
            { Borrowed: false, CreateAttempted: true, DeleteAttempted: false, Absent: false, CleanupOnly: false });
        foreach (string name in registration.InventoryOnly)
            Require(state.Resources.SingleOrDefault(r => r.Id == Resource(binding, name)) is
            { Borrowed: false, CreateAttempted: true, DeleteAttempted: false, Absent: false, CleanupOnly: false });
    }
    private static bool Ready(OwnedFixture owned)
    {
        var f = owned.Fixture;
        return f.Permission switch
        {
            SecretPermission.Get => f.State == PreparedState.Active && f.Version is not null && f.Sha256 is not null,
            SecretPermission.Delete => f.State == PreparedState.Active && f.Version is not null,
            SecretPermission.List or SecretPermission.Backup => f.State == PreparedState.Active,
            SecretPermission.Set => f.State == PreparedState.Absent && owned.Set is not null && f.Sha256 is not null,
            SecretPermission.Recover => f.State == PreparedState.Deleted && f.Version is not null && f.Sha256 is not null,
            SecretPermission.Purge => f.State == PreparedState.Deleted,
            SecretPermission.Restore => f.State == PreparedState.Absent && f.Version is not null &&
                f.Sha256 is not null && owned.Backup is not null,
            _ => false
        };
    }
    private static void Validate(Manifest m)
    {
        Require(m is not null && Text(m.Owner, 128) && m.Original is { } b && b.Selector is not null &&
            b.Selector.Nonce != Guid.Empty && b.LeaseId != Guid.Empty && b.SubscriptionId != Guid.Empty &&
            b.Query == M.QueryKind.ChangeAccessPolicies && b.Read == M.ReadKind.GetVault &&
            b.Selector.Operation == M.Operation(M.QueryKind.ChangeAccessPolicies) && Text(b.Selector.Scope, 512) &&
            b.Selector.Case is "selected-contract" or "denied-authority" or "cancellation-boundary" or
                "lost-response-no-replay" or "independent-effect" &&
            Segment(b.ResourceGroup, 90) && Segment(b.Location, 50) && b.ConnectionName is null &&
            b.VaultName is { Length: >= 3 and <= 24 } && char.IsAsciiLetter(b.VaultName[0]) &&
            char.IsAsciiLetterOrDigit(b.VaultName[^1]) && Name(b.VaultName) &&
            !b.VaultName.Contains("--", StringComparison.Ordinal) && m.ApiRevision == Revision &&
            m.Fixtures is { Length: <= 16 });
        var member = VaultAdministrationEffects.Members.Single(x => x.Operation == m.Original.Selector.Operation);
        Require(member.Variants.Contains(m.Original.Selector.Variant, StringComparer.Ordinal));
        Require(m.Fixtures.Select(f => (f.Permission, f.DeniedAuthority)).Distinct().Count() == m.Fixtures.Length);
        foreach (var aliases in m.Fixtures.GroupBy(f => f.Name, StringComparer.OrdinalIgnoreCase))
        {
            var first = aliases.First();
            Require(aliases.Count() == 1 || aliases.All(f => !Mutates(f.Permission) &&
                f.Name == first.Name && f.State == PreparedState.Active && f.Version == first.Version &&
                f.Sha256 == first.Sha256 && f.OwnedSet is null && f.Backup is null));
        }
        string[] inventory = m.InventoryOnly ?? [];
        Require(inventory.Length <= 22 && inventory.All(Name) &&
            inventory.Distinct(StringComparer.OrdinalIgnoreCase).Count() == inventory.Length &&
            !inventory.Intersect(m.Fixtures.Select(f => f.Name), StringComparer.OrdinalIgnoreCase).Any() &&
            m.Fixtures.Select(f => f.Name).Distinct(StringComparer.OrdinalIgnoreCase).Count() + inventory.Length <= 22);
        foreach (var f in m.Fixtures)
        {
            Require(Enum.IsDefined(f.Permission) && Enum.IsDefined(f.State) && Name(f.Name) &&
                !f.Name.Equals(RoleFixtureProvisioner.Canary, StringComparison.OrdinalIgnoreCase) &&
                (f.Version is null || Version(f.Version)) &&
                (f.Sha256 is null || f.Sha256.Length == 64 && f.Sha256.All(c => char.IsAsciiHexDigit(c) && !char.IsAsciiLetterLower(c))) &&
                (f.Permission == SecretPermission.Set || f.OwnedSet is null) &&
                (f.Permission == SecretPermission.Restore || f.Backup is null));
        }
    }

    private sealed class NativeTransport(VaultPolicyPermissionTrial source, Authority authority, BoundCredential credential,
        M.Binding binding, Registration registration, OwnedFixture owned, Budget budget,
        bool statusMode = false, Guid retainedDispatch = default) : HttpPipelineTransport, IDisposable
    {
        private readonly byte[] storage = new byte[source.limits.MaximumResponseBytes + 1];
        private readonly RequestBuffer requestBody = new(source.limits.MaximumResponseBytes);
        private Response? response;
        private Stream? input;
        private MemoryStream? buffered;
        private int sends;
        private NativeTransport? status;
        internal Guid Dispatch { get; private set; }
        internal bool Valid { get; private set; }
        internal int Status { get; private set; }
        internal string? RequestId { get; private set; }
        public override Request CreateRequest() => status?.CreateRequest() ?? authority.Transport.CreateRequest();
        internal NativeTransport BeginStatus(Authority observer)
        {
            Require(!statusMode && status is null && Dispatch != Guid.Empty);
            credential.Switch(observer.Credential);
            return status = new(source, observer, credential, binding, registration, owned, budget,
                statusMode: true, retainedDispatch: Dispatch);
        }
        public override void Process(HttpMessage message) => throw new Boundary();
        public override async ValueTask ProcessAsync(HttpMessage message)
        {
            if (status is not null)
            {
                await status.ProcessAsync(message).ConfigureAwait(false);
                return;
            }
            Check();
            Require(Interlocked.Increment(ref sends) == 1);
            ValidateRequest(message);
            if (message.Request.Content is { } content)
            {
                // The actual serialization task is joined too. No buffer is
                // returned or cleared while native content is still writing it.
                await content.WriteToAsync(requestBody, message.CancellationToken).ConfigureAwait(false);
                Check();
                ValidateBody(requestBody.Bytes);
            }
            else if (!statusMode && owned.Fixture.Permission is SecretPermission.Set or SecretPermission.Restore)
            {
                // An uncached native challenge removes write content before
                // transport dispatch. Reconstruct only this fixed owned intent;
                // no discovery request or externally selected body is admitted.
                using (var writer = new Utf8JsonWriter(requestBody))
                {
                    writer.WriteStartObject();
                    if (owned.Fixture.Permission == SecretPermission.Set)
                    {
                        writer.WriteString("value", owned.Set.AsSpan());
                        writer.WriteStartObject("attributes");
                        writer.WriteBoolean("enabled", true);
                        writer.WriteEndObject();
                    }
                    else writer.WriteString("value", Encode(owned.Backup!));
                    writer.WriteEndObject();
                }
                ValidateBody(requestBody.Bytes);
            }
            var issued = credential.Issued ?? await credential.GetTokenAsync(new TokenRequestContext([Audience]),
                message.CancellationToken).ConfigureAwait(false);
            Check();
            Require(Text(issued.Token, 16384) && issued.ExpiresOn > budget.ObservedAt);
            message.Request.Headers.SetValue("Authorization", "Bearer " + issued.Token);
            if (!statusMode && owned.Fixture.Permission is SecretPermission.Set or SecretPermission.Restore)
                message.Request.Content = RequestContent.Create(requestBody.Bytes);
            ValidateRequest(message);
            var headers = message.Request.Headers.Select(h => (h.Name, h.Value)).ToArray();
            if (!statusMode) source.CheckOwnership(binding, registration, owned);
            Check();
            // Atomic with Close and all other dispatches in this root. Mark
            // reads too, so they cannot interleave with another root mutation.
            if (statusMode)
            {
                source.journal.AdmitStatusRead(registration.Owner, binding.Selector, binding.LeaseId,
                    Resource(binding, owned.Fixture.Name), retainedDispatch);
                Dispatch = retainedDispatch;
            }
            else
                Dispatch = Mutates(owned.Fixture.Permission)
                    ? source.journal.BeginSelectedUpdate(registration.Owner, binding.Selector, Resource(binding, owned.Fixture.Name))
                    : source.journal.BeginSelectedRead(registration.Owner, binding.Selector, binding.LeaseId, Resource(binding, owned.Fixture.Name));
            message.BufferResponse = false;
            try { await authority.Transport.ProcessAsync(message).ConfigureAwait(false); }
            finally { if (message.HasResponse) response = message.Response; }
            Check();
            ValidateRequest(message);
            Require(headers.SequenceEqual(message.Request.Headers.Select(h => (h.Name, h.Value))));
            Require(response is not null);
            Status = response.Status;
            long? declared = Headers(response, out string requestId);
            Require(Status is 403 or 404 || Status == (statusMode ? 200 : SuccessStatus(owned.Fixture.Permission)) ||
                !statusMode && Status == 202 && Mutates(owned.Fixture.Permission));
            Require(declared is null || declared <= source.limits.MaximumResponseBytes);
            input = response.ContentStream;
            int count = 0;
            if (input is not null)
            {
                while (true)
                {
                    Check();
                    int read = await input.ReadAsync(storage.AsMemory(count), message.CancellationToken).ConfigureAwait(false);
                    Check();
                    if (read == 0) break;
                    count += read;
                    Require(count <= source.limits.MaximumResponseBytes);
                }
            }
            Require(declared is null || declared == count);
            if (Status == 204) Require(count == 0);
            else if (Status != 202 || count != 0)
            {
                Require(count > 0);
                Shape(storage.AsSpan(0, count), source.limits);
                using var document = JsonDocument.Parse(storage.AsMemory(0, count),
                    new JsonDocumentOptions { MaxDepth = source.limits.MaximumDepth });
                if (Status is 403 or 404) Error(document.RootElement, Status);
                else ValidateResponse(document.RootElement);
            }
            Check();
            input?.Dispose();
            input = null;
            // Native raw-response consumers use MemoryStream's whole-buffer
            // path: origin zero, exact length, no exhausted stream/spare bytes.
            buffered = new(storage, 0, count, writable: false, publiclyVisible: true);
            response.ContentStream = buffered;
            RequestId = requestId;
            Valid = true;

            void Check()
            {
                message.CancellationToken.ThrowIfCancellationRequested();
                budget.Check();
            }
        }

        private void ValidateRequest(HttpMessage message)
        {
            var f = owned.Fixture;
            var (path, method) = statusMode
                ? (f.Permission == SecretPermission.Delete ? "/deletedsecrets/" + f.Name : "/secrets/" + f.Name, RequestMethod.Get)
                : Route(f);
            Require(message.Request.Method == method);
            Require(message.Request.Uri.ToUri().OriginalString == Origin(binding).GetLeftPart(UriPartial.Authority) + path + "?api-version=" + Revision);
            Require(message.Request.Content is null || !statusMode && f.Permission is SecretPermission.Set or SecretPermission.Restore);
            HeaderBounds(message.Request.Headers.Select(h => (h.Name, h.Value)), 16384, 32768);
            if (message.Request.Headers.TryGetValue("Host", out string? host)) Require(host == Origin(binding).Host);
        }
        private void ValidateBody(ReadOnlyMemory<byte> bytes)
        {
            Shape(bytes.Span, source.limits);
            using var document = JsonDocument.Parse(bytes, new JsonDocumentOptions { MaxDepth = source.limits.MaximumDepth });
            var root = document.RootElement;
            Require(root.TryGetProperty("value", out var value) && value.ValueKind == JsonValueKind.String);
            if (owned.Fixture.Permission == SecretPermission.Set)
            {
                Require(Only(root, "value", "attributes") && root.TryGetProperty("attributes", out var attributes) &&
                    Only(attributes, "enabled") && attributes.TryGetProperty("enabled", out var enabled) &&
                    enabled.ValueKind == JsonValueKind.True && Hash(value.GetString()!) == owned.Fixture.Sha256);
            }
            else
            {
                Require(owned.Fixture.Permission == SecretPermission.Restore && Only(root, "value") &&
                    value.GetString() == Encode(owned.Backup!));
            }
        }
        private void ValidateResponse(JsonElement root)
        {
            var f = owned.Fixture;
            if (f.Permission == SecretPermission.Backup)
            {
                Require(Only(root, "value") && root.TryGetProperty("value", out var value) &&
                    value.ValueKind == JsonValueKind.String);
                byte[] bytes = Decode(root.GetProperty("value").GetString()!, source.limits.MaximumBackupBytes);
                CryptographicOperations.ZeroMemory(bytes);
                return;
            }
            if (f.Permission == SecretPermission.List)
            {
                Require(Only(root, "value", "nextLink") && root.TryGetProperty("value", out var rows) &&
                    rows.ValueKind == JsonValueKind.Array && rows.GetArrayLength() <= source.limits.MaximumRows &&
                    (!root.TryGetProperty("nextLink", out var next) || next.ValueKind == JsonValueKind.Null));
                bool found = false;
                var names = new HashSet<string>(StringComparer.Ordinal);
                foreach (var row in root.GetProperty("value").EnumerateArray())
                {
                    Require(Only(row, "id", "attributes", "contentType", "tags", "managed") &&
                        row.TryGetProperty("id", out var id) && id.ValueKind == JsonValueKind.String);
                    string rowId = row.GetProperty("id").GetString()!;
                    string? match = registration.Fixtures.Where(x => x.Fixture.State == PreparedState.Active)
                        .Select(x => x.Fixture.Name).Concat(registration.InventoryOnly).Distinct(StringComparer.Ordinal)
                        .SingleOrDefault(name => rowId == SecretId(binding, name, null));
                    Require(match is not null && names.Add(match));
                    Attributes(row);
                    found |= match == f.Name;
                }
                Require(found);
                return;
            }
            Require(Only(root, "id", "value", "attributes", "contentType", "tags", "kid", "managed",
                "recoveryId", "deletedDate", "scheduledPurgeDate") &&
                root.TryGetProperty("id", out var nativeId) && nativeId.ValueKind == JsonValueKind.String);
            string idText = root.GetProperty("id").GetString()!;
            string prefix = SecretId(binding, f.Name, null) + "/";
            Require(idText.StartsWith(prefix, StringComparison.Ordinal) && Version(idText[prefix.Length..]) &&
                (f.Permission == SecretPermission.Set || idText == SecretId(binding, f.Name, f.Version)));
            Attributes(root);
            if (f.Permission is SecretPermission.Get or SecretPermission.Set)
                Require(root.TryGetProperty("value", out _));
            if (root.TryGetProperty("value", out var material))
            {
                Require(material.ValueKind == JsonValueKind.String &&
                    Encoding.UTF8.GetByteCount(material.GetString()!) <= source.limits.MaximumMaterialBytes &&
                    Hash(material.GetString()!) == f.Sha256);
            }
            if (f.Permission == SecretPermission.Delete)
                Require(root.TryGetProperty("recoveryId", out var recovery) && recovery.ValueKind == JsonValueKind.String &&
                    recovery.GetString() == Origin(binding).GetLeftPart(UriPartial.Authority) + "/deletedsecrets/" + f.Name);
            else Require(!root.TryGetProperty("recoveryId", out _));
            foreach (string date in new[] { "deletedDate", "scheduledPurgeDate" })
                if (root.TryGetProperty(date, out var value))
                    Require(f.Permission == SecretPermission.Delete && value.ValueKind == JsonValueKind.Number &&
                        value.TryGetInt64(out _));
        }
        private void Attributes(JsonElement root)
        {
            Require(root.TryGetProperty("attributes", out var attributes));
            Require(Only(attributes, "enabled", "nbf", "exp", "created", "updated", "recoveryLevel", "recoverableDays") &&
                attributes.TryGetProperty("enabled", out var enabled) && enabled.ValueKind == JsonValueKind.True);
            foreach (string field in new[] { "nbf", "exp", "created", "updated" })
            {
                if (!attributes.TryGetProperty(field, out var value)) continue;
                Require(value.ValueKind == JsonValueKind.Number && value.TryGetInt64(out _));
                var instant = DateTimeOffset.FromUnixTimeSeconds(value.GetInt64());
                if (field == "nbf") Require(instant <= budget.ObservedAt);
                if (field == "exp") Require(instant > budget.ObservedAt);
            }
            foreach (string field in new[] { "contentType", "kid" })
                if (root.TryGetProperty(field, out var value)) Require(value.ValueKind == JsonValueKind.String && Text(value.GetString(), 4096));
            if (root.TryGetProperty("managed", out var managed)) Require(managed.ValueKind is JsonValueKind.True or JsonValueKind.False);
            if (root.TryGetProperty("tags", out var tags))
                Require(tags.ValueKind == JsonValueKind.Object && tags.EnumerateObject().All(p =>
                    Text(p.Name, 256) && p.Value.ValueKind == JsonValueKind.String && p.Value.GetString()!.Length <= 256));
            if (attributes.TryGetProperty("recoveryLevel", out var recovery))
                Require(recovery.ValueKind == JsonValueKind.String && recovery.GetString() is
                    "Purgeable" or "Recoverable+Purgeable" or "Recoverable" or "Recoverable+ProtectedSubscription" or
                    "CustomizedRecoverable+Purgeable" or "CustomizedRecoverable" or "CustomizedRecoverable+ProtectedSubscription");
            if (attributes.TryGetProperty("recoverableDays", out var days))
                Require(days.ValueKind == JsonValueKind.Number && days.TryGetInt32(out int count) && count is >= 7 and <= 90);
        }
        public void Dispose()
        {
            try
            {
                try { input?.Dispose(); }
                finally
                {
                    try { buffered?.Dispose(); }
                    finally
                    {
                        try { response?.Dispose(); }
                        finally { status?.Dispose(); }
                    }
                }
            }
            finally
            {
                CryptographicOperations.ZeroMemory(storage);
                requestBody.Dispose();
            }
        }
    }

    private sealed class RequestBuffer(int maximum) : Stream
    {
        private readonly byte[] storage = new byte[maximum];
        private int count;
        internal ReadOnlyMemory<byte> Bytes => storage.AsMemory(0, count);
        public override bool CanRead => false;
        public override bool CanSeek => false;
        public override bool CanWrite => true;
        public override long Length => count;
        public override long Position { get => count; set => throw new Boundary(); }
        public override void Write(byte[] buffer, int offset, int length) => Write(buffer.AsSpan(offset, length));
        public override void Write(ReadOnlySpan<byte> buffer)
        {
            Require(buffer.Length <= storage.Length - count);
            buffer.CopyTo(storage.AsSpan(count));
            count += buffer.Length;
        }
        public override Task WriteAsync(byte[] buffer, int offset, int length, CancellationToken cancellationToken)
        {
            cancellationToken.ThrowIfCancellationRequested();
            Write(buffer, offset, length);
            return Task.CompletedTask;
        }
        public override ValueTask WriteAsync(ReadOnlyMemory<byte> buffer, CancellationToken cancellationToken = default)
        {
            cancellationToken.ThrowIfCancellationRequested();
            Write(buffer.Span);
            return ValueTask.CompletedTask;
        }
        public override void Flush() { }
        public override int Read(byte[] buffer, int offset, int count) => throw new Boundary();
        public override long Seek(long offset, SeekOrigin origin) => throw new Boundary();
        public override void SetLength(long value) => throw new Boundary();
        protected override void Dispose(bool disposing) { CryptographicOperations.ZeroMemory(storage); base.Dispose(disposing); }
    }
    private sealed class BoundCredential(TokenCredential inner, Budget budget) : TokenCredential
    {
        private TokenCredential current = inner;
        private int calls;
        internal AccessToken? Issued { get; private set; }
        internal void Switch(TokenCredential next)
        {
            current = next;
            Issued = null;
            calls = 0;
        }
        public override AccessToken GetToken(TokenRequestContext requestContext, CancellationToken cancellationToken) => throw new Boundary();
        public override async ValueTask<AccessToken> GetTokenAsync(TokenRequestContext requestContext, CancellationToken cancellationToken)
        {
            cancellationToken.ThrowIfCancellationRequested();
            budget.Check();
            Require(requestContext.Scopes.Length == 1 && requestContext.Scopes[0] == Audience &&
                Interlocked.Increment(ref calls) == 1);
            // Same invocation-bound rule as VaultNetworkReadCollector: warm
            // SDK challenges and a cold transport share one issuance. Cached
            // tenant/claims never nominate the borrowed host authority.
            var issued = await current.GetTokenAsync(new TokenRequestContext([Audience]), cancellationToken).ConfigureAwait(false);
            cancellationToken.ThrowIfCancellationRequested();
            budget.Check();
            Require(Text(issued.Token, 16384) && issued.ExpiresOn > budget.ObservedAt);
            Issued = issued;
            return issued;
        }
    }
    private sealed class Budget(TimeProvider time, DateTimeOffset armedAt, long timestamp, TimeSpan timeout)
    {
        private DateTimeOffset lastWall = DateTimeOffset.MinValue;
        private long lastStamp = long.MinValue;
        private bool invalid;
        internal DateTimeOffset ObservedAt => lastWall;
        internal CancellationTokenSource? Deadline { get; set; }
        internal void Check()
        {
            Require(!invalid);
            var wall = time.GetUtcNow();
            long stamp = time.GetTimestamp();
            if (wall < armedAt || stamp < timestamp || wall < lastWall || stamp < lastStamp)
            {
                invalid = true;
                throw new Boundary();
            }
            TimeSpan monotonic = time.GetElapsedTime(timestamp, stamp), elapsed = wall - armedAt;
            Require(monotonic >= TimeSpan.Zero && elapsed >= TimeSpan.Zero);
            lastWall = wall;
            lastStamp = stamp;
            TimeSpan remaining = timeout - (monotonic > elapsed ? monotonic : elapsed);
            if (remaining <= TimeSpan.Zero) throw new Boundary(Failure.Deadline);
            Deadline?.CancelAfter(remaining);
        }
    }

    private static void ValidateProperties(SecretProperties p, M.Binding binding, PreparedFixture fixture, bool exactVersion)
    {
        Require(p.Name == fixture.Name && p.VaultUri == Origin(binding) && Version(p.Version) &&
            p.Id?.OriginalString == SecretId(binding, fixture.Name, p.Version) &&
            (!exactVersion || p.Version == fixture.Version));
    }
    private static void Shape(ReadOnlySpan<byte> bytes, Limits limits)
    {
        var reader = new Utf8JsonReader(bytes, new JsonReaderOptions { MaxDepth = limits.MaximumDepth });
        var stack = new Stack<HashSet<string>?>();
        int nodes = 0, rows = 0;
        while (reader.Read())
        {
            Require(++nodes <= limits.MaximumNodes);
            if (reader.TokenType == JsonTokenType.StartObject)
            {
                Require(++rows <= limits.MaximumRows);
                stack.Push(new(StringComparer.OrdinalIgnoreCase));
            }
            else if (reader.TokenType == JsonTokenType.StartArray) stack.Push(null);
            else if (reader.TokenType is JsonTokenType.EndObject or JsonTokenType.EndArray) stack.Pop();
            else if (reader.TokenType == JsonTokenType.PropertyName)
                Require(stack.Count > 0 && stack.Peek() is { } names && names.Add(reader.GetString()!));
        }
        Require(nodes > 0 && stack.Count == 0);
    }
    private static void Error(JsonElement root, int status)
    {
        Require(Only(root, "error") && root.TryGetProperty("error", out var error) &&
            error.TryGetProperty("code", out var code) && code.ValueKind == JsonValueKind.String &&
            code.GetString() == (status == 403 ? "Forbidden" : "SecretNotFound"));
        ValidateError(root.GetProperty("error"));
    }
    private static void ValidateError(JsonElement error)
    {
        Require(Only(error, "code", "message", "innererror", "details") &&
            error.TryGetProperty("code", out var code) && code.ValueKind == JsonValueKind.String && Text(code.GetString(), 128));
        if (error.TryGetProperty("message", out var message)) Require(message.ValueKind == JsonValueKind.String);
        if (error.TryGetProperty("innererror", out var inner)) ValidateError(inner);
        if (error.TryGetProperty("details", out var details))
        {
            Require(details.ValueKind == JsonValueKind.Array);
            foreach (var detail in details.EnumerateArray()) ValidateError(detail);
        }
    }
    private static long? Headers(Response response, out string requestId)
    {
        HeaderBounds(response.Headers.Select(h => (h.Name, h.Value)), 4096, 16384);
        foreach (string name in new[] { "Content-Range", "Content-Encoding", "Location", "Azure-AsyncOperation",
            "Operation-Location", "Transfer-Encoding" }) Require(!response.Headers.Contains(name));
        requestId = Single(response, "x-ms-request-id");
        Require(Segment(requestId, 128));
        if (response.Status != 204)
        {
            string[] type = Single(response, "Content-Type").Split(';', StringSplitOptions.TrimEntries);
            Require(type.Length is 1 or 2 && type[0].Equals("application/json", StringComparison.OrdinalIgnoreCase) &&
                (type.Length == 1 || type[1].Equals("charset=utf-8", StringComparison.OrdinalIgnoreCase)));
        }
        if (!response.Headers.Contains("Content-Length")) return null;
        Require(long.TryParse(Single(response, "Content-Length"), NumberStyles.None, CultureInfo.InvariantCulture, out long length) && length >= 0);
        return length;
    }
    private static void HeaderBounds(IEnumerable<(string Name, string Value)> headers, int maximumValue, int maximumBytes)
    {
        int count = 0, bytes = 0;
        var names = new HashSet<string>(StringComparer.OrdinalIgnoreCase);
        foreach (var (name, value) in headers)
        {
            Require(++count <= 32 && name.Length is > 0 and <= 128 && value.Length <= maximumValue &&
                name.All(c => char.IsAsciiLetterOrDigit(c) || c == '-') && names.Add(name) &&
                !value.Any(c => !char.IsAscii(c) || char.IsControl(c) && c != '\t'));
            bytes += name.Length + value.Length;
            Require(bytes <= maximumBytes);
        }
    }
    private static string Single(Response response, string name)
    {
        Require(response.Headers.TryGetValues(name, out var source));
        string[] values = source.Take(2).ToArray();
        Require(values.Length == 1);
        return values[0];
    }
    private static byte[] Decode(string text, int maximum)
    {
        Require(text.Length > 0 && text.Length <= (maximum + 2) / 3 * 4 &&
            text.All(c => char.IsAsciiLetterOrDigit(c) || c is '-' or '_') && text.Length % 4 != 1);
        byte[] result = Convert.FromBase64String(text.Replace('-', '+').Replace('_', '/') + new string('=', (4 - text.Length % 4) % 4));
        if (result.Length is > 0 && result.Length <= maximum && Encode(result) == text) return result;
        CryptographicOperations.ZeroMemory(result);
        throw new Boundary();
    }
    private static string Encode(byte[] bytes) => Convert.ToBase64String(bytes).TrimEnd('=').Replace('+', '-').Replace('/', '_');
    private static string Hash(string value)
    {
        byte[] bytes = new UTF8Encoding(false, true).GetBytes(value);
        try { return Convert.ToHexString(SHA256.HashData(bytes)); }
        finally { CryptographicOperations.ZeroMemory(bytes); }
        // Native JSON and SDK material/token strings are immutable; no erasure
        // claim is made for them or for host-owned transport instrumentation.
    }
    private static (string Path, RequestMethod Method) Route(PreparedFixture f) => f.Permission switch
    {
        SecretPermission.Get => ("/secrets/" + f.Name + "/" + f.Version, RequestMethod.Get),
        SecretPermission.List => ("/secrets/", RequestMethod.Get),
        SecretPermission.Set => ("/secrets/" + f.Name, RequestMethod.Put),
        SecretPermission.Delete => ("/secrets/" + f.Name, RequestMethod.Delete),
        SecretPermission.Recover => ("/deletedsecrets/" + f.Name + "/recover", RequestMethod.Post),
        SecretPermission.Backup => ("/secrets/" + f.Name + "/backup", RequestMethod.Post),
        SecretPermission.Restore => ("/secrets/restore", RequestMethod.Post),
        SecretPermission.Purge => ("/deletedsecrets/" + f.Name, RequestMethod.Delete),
        _ => throw new Boundary()
    };
    private static int SuccessStatus(SecretPermission permission) => permission == SecretPermission.Purge ? 204 : 200;
    private static bool Mutates(SecretPermission permission) => permission is not (SecretPermission.Get or SecretPermission.List or SecretPermission.Backup);
    private static Uri Origin(M.Binding b) => new("https://" + b.VaultName + ".vault.azure.net");
    private static string VaultId(M.Binding b) =>
        $"/subscriptions/{b.SubscriptionId:D}/resourceGroups/{b.ResourceGroup}/providers/Microsoft.KeyVault/vaults/{b.VaultName}";
    private static string Resource(M.Binding b, string name) => VaultId(b) + "/secrets/" + name;
    private static string SecretId(M.Binding b, string name, string? version) =>
        Origin(b).GetLeftPart(UriPartial.Authority) + "/secrets/" + name + (version is null ? "" : "/" + version);
    private static bool Version(string? value) => value is { Length: 32 } && value.All(char.IsAsciiHexDigit);
    private static bool Name(string? value) => Text(value, 127) && value.All(c => char.IsAsciiLetterOrDigit(c) || c == '-');
    private static bool Segment(string? value, int maximum) => Text(value, maximum) && value is not ("." or "..") &&
        value.All(c => char.IsAsciiLetterOrDigit(c) || c is '-' or '_' or '.');
    private static bool Text([NotNullWhen(true)] string? value, int maximum) =>
        !string.IsNullOrWhiteSpace(value) && value.Length <= maximum && !value.Any(char.IsControl);
    private static bool Only(JsonElement value, params string[] names) => value.ValueKind == JsonValueKind.Object &&
        value.EnumerateObject().All(p => names.Contains(p.Name, StringComparer.Ordinal));
    private static bool Valid(Authority? authority) => authority is not null && Text(authority.Label, 128) &&
        authority.Credential is not null && authority.Transport is not null;
    private static void Require([DoesNotReturnIf(false)] bool condition)
    {
        if (!condition) throw new Boundary();
    }
    private sealed class Boundary(Failure reason = Failure.Boundary) : Exception("policy-trial-boundary")
    {
        internal Failure Reason { get; } = reason;
    }

    public async ValueTask DisposeAsync()
    {
        TaskCompletionSource completion;
        Task[] drains;
        bool first;
        lock (gate)
        {
            first = disposal is null;
            completion = disposal ??= new(TaskCreationOptions.RunContinuationsAsynchronously);
            closed = true;
            foreach (var registration in windows.Values.Where(r => !r.Consumed))
            {
                registration.Consumed = true;
                registration.Release();
            }
            drains = windows.Values.Select(r => r.Drained.Task).ToArray();
        }
        if (!first) { await completion.Task.ConfigureAwait(false); return; }
        try
        {
            try { stop.Cancel(); }
            catch (Exception) { /* A host callback cannot bypass draining. */ }
            await Task.WhenAll(drains).ConfigureAwait(false);
        }
        finally
        {
            stop.Dispose();
            completion.TrySetResult();
        }
    }
    public override string ToString() => "[VaultPolicyPermissionTrial]";
}
