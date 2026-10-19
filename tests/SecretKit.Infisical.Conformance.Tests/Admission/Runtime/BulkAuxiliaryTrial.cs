using SecretKit.Core;
using SecretKit.TestFixtures;

namespace SecretKit.Infisical.Conformance.Tests;

internal sealed class BulkAuxiliaryTrial(IBulkAuxiliarySource source, BulkAuxiliaryRoot root,
    int seconds) : IAsyncDisposable
{
    private BulkAuxiliaryBinding? binding;
    private BulkAuxiliaryFence? fence;
    private bool busy, failed, observed, closed;
    private long sequence;
    private DateTimeOffset at;
    private readonly HashSet<string> events = [];

    internal static async ValueTask<BulkAuxiliaryTrial> OpenAsync(IBulkAuxiliarySource source,
        BulkAuxiliaryRoot root, BulkAuxiliaryRow[] baseline, int seconds,
        Action<BulkAuxiliaryTrial> retain, CancellationToken token)
    {
        BulkAuxiliaryContract.Require(seconds is >= 1 and <= 300 && root.Source == source.Kind &&
            Text(root.Id) && Text(root.CaseIdentity) && Text(root.ProviderRevision) &&
            Text(root.DeploymentId) && Text(root.Nonce) && Text(source.Identity) &&
            source.Identity is not ("setup" or "runtime" or "denied" or "administrative" or "observer") &&
            root.Folder.StartsWith(root.Namespace.TrimEnd('/') + "/sk-", StringComparison.Ordinal) &&
            Guid.TryParse(root.FolderId, out _) && Enum.IsDefined(root.Role), "missing-input");
        var trial = new BulkAuxiliaryTrial(source, root, seconds);
        retain(trial); // Cleanup ownership precedes Open, including a lost reply.
        trial.busy = trial.failed = true;
        using var deadline = trial.Deadline(token);
        var facts = await source.OpenAsync(root, baseline, deadline.Token);
        try
        {
            BulkAuxiliaryContract.Require(facts.Root == root && Text(facts.Registration) &&
                facts.SourceIdentity == source.Identity && facts.ClockAuthority == "provider-application-clock" &&
                Text(facts.ClockEpoch) && facts.At != default && facts.At.Offset == TimeSpan.Zero &&
                facts.Sequence >= 0 && facts.NamespaceCollisionCheckedBeforeSetup &&
                facts.RootInitiallyAbsent && facts.ProtectedStorageQualified &&
                facts.OriginalCaptureArmed && facts.BorrowedPreserved &&
                BulkAuxiliaryContract.Equal(facts.Baseline, baseline, true));
            trial.binding = facts;
            trial.sequence = facts.Sequence; trial.at = facts.At;
            trial.busy = trial.failed = false;
            return trial;
        }
        finally { foreach (var row in facts.Baseline) row.Erase(); }
    }

    internal async ValueTask CompleteAsync(DispatchEvidence receipt, CancellationToken token)
    {
        Enter();
        try
        {
            using var deadline = Deadline(token);
            var facts = await source.CompleteAsync(root, receipt, deadline.Token);
            BulkAuxiliaryContract.Require(binding is not null && facts.Root == root &&
                facts.Registration == binding.Registration && facts.Receipt == receipt &&
                events.Add(facts.EventId) && Text(facts.EventId) && Next(facts.Sequence, facts.At) &&
                facts.ExactOriginalScopeIdentityMethodShape && facts.Settled &&
                facts.LateWorkExcluded && facts.NoReplay && facts.OriginalRequests is >= 0 and <= 1 &&
                facts.CommittedRows >= 0 && (facts.OriginalRequests == 0 ? facts.RequestId is null :
                    Text(facts.RequestId)), "observer-unavailable");
            BulkAuxiliaryContract.Require(
                (receipt != DispatchEvidence.NotDispatched || facts.OriginalRequests == 0) &&
                (receipt is not (DispatchEvidence.NotDispatched or DispatchEvidence.Rejected) || facts.CommittedRows == 0) &&
                (facts.CommittedRows == 0 || facts.OriginalRequests == 1), "effect-mismatch");
            fence = facts; failed = false;
        }
        finally { busy = false; }
    }

    internal async ValueTask ObserveAsync(BulkAuxiliaryRow[] expected, CancellationToken token)
    {
        BulkAuxiliaryContract.Require(fence is not null && !observed);
        Enter(); observed = true;
        try
        {
            using var deadline = Deadline(token);
            var facts = await source.ObserveAsync(root, deadline.Token);
            try
            {
                BulkAuxiliaryContract.Require(facts.Root == root && facts.Registration == binding!.Registration &&
                    facts.FenceEvent == fence!.EventId && Text(facts.EventId) && events.Add(facts.EventId) &&
                    Next(facts.Sequence, facts.At));
                BulkAuxiliaryContract.Require(facts.FullBatchMappedBackendInventory &&
                    facts.IndependentProtectedStorageRead && facts.BorrowedPreserved &&
                    BulkAuxiliaryContract.Equal(facts.Rows, expected, true), "effect-mismatch");
                failed = false;
            }
            finally { foreach (var row in facts.Rows) row.Erase(); }
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
            BulkAuxiliaryContract.Require(facts.Root == root && facts.OriginalSettled &&
                facts.LateWorkExcluded && facts.RootAbsent && facts.FullInventoryEmpty &&
                facts.BorrowedPreserved && facts.PrivateCopiesReleased &&
                facts.Registrations == 0 && facts.PendingDeliveries == 0, "cleanup-incomplete");
        }
        catch (Exception error) when (error is OperationCanceledException or NativeCaseFailureException)
        { throw new NativeCaseFailureException("cleanup-incomplete"); }
    }
    private void Enter()
    {
        BulkAuxiliaryContract.Require(!busy && !failed && !closed);
        busy = failed = true;
    }
    private bool Next(long cursor, DateTimeOffset time)
    {
        if (cursor <= sequence || time == default || time.Offset != TimeSpan.Zero || time < at) return false;
        sequence = cursor; at = time; return true;
    }
    private CancellationTokenSource Deadline(CancellationToken token)
    {
        var deadline = CancellationTokenSource.CreateLinkedTokenSource(token);
        deadline.CancelAfter(TimeSpan.FromSeconds(seconds));
        return deadline;
    }
    private static bool Text(string? value) => value is { Length: > 0 and <= 2048 } &&
        !string.IsNullOrWhiteSpace(value) && !value.Any(char.IsControl);
}
