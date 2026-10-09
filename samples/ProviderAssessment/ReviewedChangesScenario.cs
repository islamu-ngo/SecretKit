using System.Text.Json.Serialization;
using SecretKit.AzureKeyVault;
using SecretKit.Core;
using SecretKit.Infisical;

namespace SecretKit.Samples.ProviderAssessment;

public enum ReviewApproval
{
    NotApproved,
    Approved
}

public enum ReviewedChangeOperation
{
    InfisicalCreate,
    InfisicalUpdateValue,
    AzureSet
}

/// <summary>
/// An exact consumer selection, not a callback or arbitrary endpoint. Material and clients
/// remain caller-owned. Keep material alive until ExecuteAsync returns its task: it copies
/// approved inputs synchronously before any work starts. Selection exposes no disposable payload.
/// Review approval is a caller decision, not provider authorization or a provider approval.
/// </summary>
public sealed class ReviewedChange
{
    private readonly InfisicalClient? _infisical;
    private readonly AzureKeyVaultClient? _azure;
    private readonly SecretMaterial _material;

    private ReviewedChange(ReviewedChangeOperation operation, ReviewApproval approval,
        SecretReference target, SecretMaterial material, InfisicalClient? infisical, AzureKeyVaultClient? azure)
    {
        ArgumentNullException.ThrowIfNull(target);
        ArgumentNullException.ThrowIfNull(material);
        if (!Enum.IsDefined(approval))
        {
            throw new ArgumentOutOfRangeException(nameof(approval));
        }

        Operation = operation;
        Approval = approval;
        Target = target;
        _material = material;
        _infisical = infisical;
        _azure = azure;
    }

    public ReviewedChangeOperation Operation { get; }
    public ReviewApproval Approval { get; }
    [JsonIgnore]
    internal SecretReference Target { get; }

    public static ReviewedChange InfisicalCreate(ReviewApproval approval, InfisicalClient client,
        SecretReference target, SecretMaterial material)
    {
        ArgumentNullException.ThrowIfNull(client);
        return new(ReviewedChangeOperation.InfisicalCreate, approval, target, material, client, null);
    }

    public static ReviewedChange InfisicalUpdateValue(ReviewApproval approval, InfisicalClient client,
        SecretReference target, SecretMaterial material)
    {
        ArgumentNullException.ThrowIfNull(client);
        return new(ReviewedChangeOperation.InfisicalUpdateValue, approval, target, material, client, null);
    }

    public static ReviewedChange AzureSet(ReviewApproval approval, AzureKeyVaultClient client,
        SecretReference target, SecretMaterial material)
    {
        ArgumentNullException.ThrowIfNull(client);
        return new(ReviewedChangeOperation.AzureSet, approval, target, material, null, client);
    }

    internal SecretMaterial CopyMaterial() => _material.Copy();

    internal async ValueTask<SecretStatus> DispatchAsync(SecretMaterial material,
        MutationReceipt receipt, CancellationToken cancellationToken)
    {
        switch (Operation)
        {
            case ReviewedChangeOperation.InfisicalCreate:
                return (await _infisical!.CreateAsync(Target, material, receipt, cancellationToken)).Status;
            case ReviewedChangeOperation.InfisicalUpdateValue:
                return (await _infisical!.UpdateValueAsync(Target, material, receipt, cancellationToken)).Status;
            case ReviewedChangeOperation.AzureSet:
                return (await _azure!.SetSecretAsync(new AzureSetSecretRequest(Target, material),
                    receipt, cancellationToken)).Status;
            default:
                throw new InvalidOperationException("Unknown reviewed operation.");
        }
    }

    public override string ToString() => $"[ReviewedChange:{Operation}:{Approval}]";
}

public enum ReviewedChangeProgress
{
    Queued,
    Completed,
    Canceled
}

/// <summary>Safe index correlation and caller-held evidence, available even when execution throws.</summary>
public sealed class ReviewedChangeResult
{
    private readonly object _gate = new();
    private SecretStatus? _status;
    private ReviewedChangeProgress _progress;

    internal ReviewedChangeResult(int index, SecretReference target)
    {
        Index = index;
        Receipt = new MutationReceipt(target);
    }

    public int Index { get; }
    [JsonIgnore]
    public MutationReceipt Receipt { get; }
    public DispatchEvidence Evidence => Receipt.Evidence;
    public SecretStatus? Status { get { lock (_gate) { return _status; } } }
    public ReviewedChangeProgress Progress { get { lock (_gate) { return _progress; } } }

    internal void Complete(SecretStatus status)
    {
        lock (_gate)
        {
            _status = Evidence == DispatchEvidence.Pending ? SecretStatus.Pending : status;
            _progress = ReviewedChangeProgress.Completed;
        }
    }

    internal void Cancel()
    {
        lock (_gate)
        {
            if (_progress == ReviewedChangeProgress.Completed)
            {
                return;
            }

            _status = Evidence switch
            {
                DispatchEvidence.Applied => SecretStatus.Success,
                DispatchEvidence.Pending => SecretStatus.Pending,
                DispatchEvidence.Conflict => SecretStatus.Conflict,
                DispatchEvidence.Rejected => SecretStatus.Denied,
                DispatchEvidence.PossiblyDispatched => SecretStatus.Unknown,
                _ => null
            };
            _progress = ReviewedChangeProgress.Canceled;
        }
    }

    public override string ToString() => $"[ReviewedChangeResult:{Index}:{Progress}:{Evidence}]";
}

/// <summary>
/// A single consumer-owned, finite reviewed batch. At most MaximumItems inputs and
/// MaximumConcurrency awaited native calls are admitted. Fixed workers claim the next
/// index only after finishing their previous item; no task-per-item fanout or unbounded queue.
/// Completion order does not reorder results. Concurrent writes to the same target have
/// native ordering only; select concurrency one when consumer order is required.
/// No persistence, transaction, rollback, retry or automatic reconciliation is implied.
/// </summary>
public sealed class ReviewedChangesScenario
{
    public const int MaximumItems = 128;
    public const int MaximumConcurrency = 16;
    private readonly ReviewedChange[] _items;
    private readonly int _concurrency;
    private int _executed;

    public ReviewedChangesScenario(IEnumerable<ReviewedChange> items, int concurrency)
    {
        ArgumentNullException.ThrowIfNull(items);
        if (concurrency is < 1 or > MaximumConcurrency)
        {
            throw new ArgumentOutOfRangeException(nameof(concurrency));
        }

        // Stop enumerating an oversized or infinite input at the first inadmissible item.
        _items = items.Take(MaximumItems + 1).ToArray();
        if (_items.Length is < 1 or > MaximumItems || _items.Any(item => item is null))
        {
            throw new ArgumentException("Select a nonempty bounded batch of reviewed items.", nameof(items));
        }

        _concurrency = concurrency;
        Results = Array.AsReadOnly(_items.Select((item, index) => new ReviewedChangeResult(index, item.Target)).ToArray());
    }

    [JsonIgnore]
    public IReadOnlyList<ReviewedChangeResult> Results { get; }

    public async Task<IReadOnlyList<ReviewedChangeResult>> ExecuteAsync(CancellationToken cancellationToken = default)
    {
        if (Interlocked.Exchange(ref _executed, 1) != 0)
        {
            throw new InvalidOperationException("A reviewed batch cannot be executed again.");
        }

        var material = new SecretMaterial?[_items.Length];
        try
        {
            cancellationToken.ThrowIfCancellationRequested();
            for (int index = 0; index < _items.Length; index++)
            {
                if (_items[index].Approval != ReviewApproval.Approved)
                {
                    Results[index].Complete(SecretStatus.Denied);
                    continue;
                }

                try
                {
                    material[index] = _items[index].CopyMaterial();
                }
                catch (ObjectDisposedException)
                {
                    Results[index].Complete(SecretStatus.Invalid);
                }
            }

            int next = -1;
            var workers = new Task[Math.Min(_concurrency, _items.Length)];
            for (int worker = 0; worker < workers.Length; worker++)
            {
                workers[worker] = WorkAsync();
            }

            await Task.WhenAll(workers);
            cancellationToken.ThrowIfCancellationRequested();
            return Results;

            async Task WorkAsync()
            {
                while (true)
                {
                    cancellationToken.ThrowIfCancellationRequested();
                    int index = Interlocked.Increment(ref next);
                    if (index >= _items.Length)
                    {
                        return;
                    }

                    if (material[index] is not { } owned)
                    {
                        continue;
                    }

                    try
                    {
                        cancellationToken.ThrowIfCancellationRequested();
                        Results[index].Complete(await _items[index].DispatchAsync(
                            owned, Results[index].Receipt, cancellationToken));
                    }
                    catch (OperationCanceledException)
                    {
                        Results[index].Cancel();
                        throw;
                    }
                    catch (Exception)
                    {
                        // Keep host/transport exception payloads out of reports; retain dispatch uncertainty.
                        Results[index].Complete(Results[index].Evidence == DispatchEvidence.NotDispatched
                            ? SecretStatus.Unavailable : SecretStatus.Unknown);
                    }
                    finally
                    {
                        owned.Dispose();
                    }
                }
            }
        }
        catch (OperationCanceledException)
        {
            foreach (ReviewedChangeResult result in Results)
            {
                result.Cancel();
            }

            throw;
        }
        finally
        {
            foreach (SecretMaterial? owned in material)
            {
                owned?.Dispose();
            }
        }
    }

    public override string ToString() => "[ReviewedChangesScenario]";
}
