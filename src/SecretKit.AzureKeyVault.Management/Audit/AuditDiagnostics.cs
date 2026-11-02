using System.Globalization;
using System.Text.Json.Serialization;
using Azure.Core;
using Azure.Core.Pipeline;
using Azure.Monitor.Query;
using Azure.Monitor.Query.Models;
using SecretKit.Core;

namespace SecretKit.AzureKeyVault.Management;

/// <summary>A bounded classification of native audit operation names, not proof of a caller's current permissions.</summary>
public enum AuditOperation
{
    /// <summary>The native operation name was not recognized.</summary>
    Unknown,
    /// <summary>The audit row describes a secret read.</summary>
    SecretGet,
    /// <summary>The audit row describes secret enumeration.</summary>
    SecretList,
    /// <summary>The audit row describes a secret version write.</summary>
    SecretSet,
    /// <summary>The audit row describes secret deletion.</summary>
    SecretDelete,
    /// <summary>The audit row describes recovery of a deleted secret.</summary>
    SecretRecover,
    /// <summary>The audit row describes acquiring a native backup.</summary>
    SecretBackup,
    /// <summary>The audit row describes restoring a native backup.</summary>
    SecretRestore,
    /// <summary>The audit row describes purging a deleted secret.</summary>
    SecretPurge
}
/// <summary>The native outcome category projected from an audit row.</summary>
public enum AuditResultKind
{
    /// <summary>The reported outcome was not recognized.</summary>
    Unknown,
    /// <summary>The row reports native success.</summary>
    Success,
    /// <summary>The row reports native failure.</summary>
    Failure
}
/// <summary>A bounded reason that audit collection failed or did not establish completeness.</summary>
public enum AuditError
{
    /// <summary>No collection error or local truncation was observed.</summary>
    None,
    /// <summary>The monitoring provider reported partial query results.</summary>
    PartialFailure,
    /// <summary>The query or transport failed without an accepted complete result.</summary>
    QueryFailure,
    /// <summary>The response violated the selected audit schema or scope.</summary>
    InvalidResponse,
    /// <summary>More rows existed than the selected local bound permits.</summary>
    RowLimit,
    /// <summary>The cooperative query or batch time budget expired.</summary>
    Deadline
}

/// <summary>
/// One bounded AzureDiagnostics AuditEvent window for exactly one vault. There is no raw KQL,
/// additional workspace, arbitrary column selection, cross-resource query or synthetic cursor.
/// </summary>
public sealed class AuditQuery
{
    /// <summary>Defines one bounded half-open time window with fixed projected columns and one vault filter.</summary>
    /// <param name="vault">The exact vault whose audit records are selected.</param>
    /// <param name="start">The inclusive window start.</param>
    /// <param name="end">The exclusive end, later than start and at most one day after it.</param>
    /// <param name="maximumRows">The local retained-row limit, from 1 through 1000.</param>
    /// <param name="timeout">A one-second to two-minute budget; null selects 30 seconds.</param>
    /// <param name="workspaceId">A nonempty workspace identifier, or null for resource-scoped querying.</param>
    /// <exception cref="ArgumentNullException">The vault is null.</exception>
    /// <exception cref="ArgumentException">The window, row bound or workspace identifier is invalid.</exception>
    /// <exception cref="ArgumentOutOfRangeException">The timeout is outside its supported range.</exception>
    public AuditQuery(VaultScope vault, DateTimeOffset start, DateTimeOffset end, int maximumRows = 100,
        TimeSpan? timeout = null, Guid? workspaceId = null)
    {
        ArgumentNullException.ThrowIfNull(vault);
        if (end <= start || end - start > TimeSpan.FromDays(1) || maximumRows is < 1 or > 1000)
        {
            throw new ArgumentException("Invalid bounded audit window.");
        }

        Vault = vault;
        Start = start;
        End = end;
        MaximumRows = maximumRows;
        Timeout = timeout ?? TimeSpan.FromSeconds(30);
        if (Timeout < TimeSpan.FromSeconds(1) || Timeout > TimeSpan.FromMinutes(2))
        {
            throw new ArgumentOutOfRangeException(nameof(timeout));
        }

        WorkspaceId = workspaceId is null ? null : ManagementScope.Identifier(workspaceId.Value);
    }

    /// <summary>Gets the protected vault filter; no query can select a second resource.</summary>
    [JsonIgnore]
    public VaultScope Vault { get; }
    /// <summary>Gets the inclusive query-window start.</summary>
    public DateTimeOffset Start { get; }
    /// <summary>Gets the exclusive query-window end.</summary>
    public DateTimeOffset End { get; }
    /// <summary>Gets the retained-row limit; one extra row is requested to detect truncation.</summary>
    public int MaximumRows { get; }
    /// <summary>Gets the single-page contract; no synthetic continuation cursor is supported.</summary>
    [System.Diagnostics.CodeAnalysis.SuppressMessage("Performance", "CA1822", Justification = "The one-page bound belongs to each query's instance budget contract.")]
    public int MaximumPages => 1;
    /// <summary>Gets the cooperative query deadline and native server timeout.</summary>
    public TimeSpan Timeout { get; }
    /// <summary>Gets the selected workspace identifier, or null for resource-scoped querying.</summary>
    [JsonIgnore]
    public Guid? WorkspaceId { get; }

    internal string QueryText =>
        $"AzureDiagnostics | where ResourceProvider == 'MICROSOFT.KEYVAULT' and Category == 'AuditEvent' " +
        $"and _ResourceId =~ '{Vault.ResourceId}' " +
        $"| where TimeGenerated >= datetime({Start.UtcDateTime.ToString("O", CultureInfo.InvariantCulture)}) " +
        $"and TimeGenerated < datetime({End.UtcDateTime.ToString("O", CultureInfo.InvariantCulture)}) " +
        $"| project TimeGenerated, OperationName, ResultType, _ResourceId, Category " +
        $"| order by TimeGenerated asc, OperationName asc, ResultType asc | take {MaximumRows + 1}";

    /// <summary>Returns a marker without vault or workspace coordinates.</summary>
    public override string ToString() => "[AuditQuery]";
}

/// <summary>A minimal audit projection without principal, address, request body or secret material.</summary>
/// <param name="timestamp">The provider-reported event time.</param>
/// <param name="operation">The bounded operation classification.</param>
/// <param name="result">The bounded reported outcome.</param>
public sealed class AuditEvent(DateTimeOffset timestamp, AuditOperation operation, AuditResultKind result)
{
    /// <summary>Gets the provider-reported event timestamp.</summary>
    public DateTimeOffset Timestamp { get; } = timestamp;
    /// <summary>Gets the native operation category, or Unknown for an unrecognized name.</summary>
    public AuditOperation Operation { get; } = operation;
    /// <summary>Gets the native reported result category.</summary>
    public AuditResultKind Result { get; } = result;
    /// <summary>Returns a marker without the event contents.</summary>
    public override string ToString() => "[AuditEvent]";
}

/// <summary>A bounded audit observation with explicit completeness and failure information.</summary>
public sealed class AuditQueryResult
{
    internal AuditQueryResult(SecretStatus status, IReadOnlyList<AuditEvent> events, bool complete, AuditError error)
    {
        Status = status;
        Events = Array.AsReadOnly(events.ToArray());
        Complete = complete;
        Error = error;
    }

    /// <summary>Gets the bounded query status; Success may still contain partial or truncated results.</summary>
    public SecretStatus Status { get; }
    /// <summary>Gets copied accepted event projections; inspect completeness before treating them as exhaustive.</summary>
    [JsonIgnore]
    public IReadOnlyList<AuditEvent> Events { get; }
    /// <summary>Gets whether no native partial error or local truncation was observed.</summary>
    public bool Complete { get; }
    /// <summary>Gets the collection failure or incompleteness reason.</summary>
    public AuditError Error { get; }
    /// <summary>Gets one for an accepted query response and zero for a failed query.</summary>
    public int Pages => Status == SecretStatus.Success ? 1 : 0;
    /// <summary>Always false: historical audit events do not prove current intended-identity secret delivery.</summary>
    [System.Diagnostics.CodeAnalysis.SuppressMessage("Performance", "CA1822", Justification = "The absence of runtime-delivery proof belongs to each query result's evidence contract.")]
    public bool RuntimeDeliveryProven => false;
    /// <summary>Returns status and completeness without events or resource coordinates.</summary>
    public override string ToString() => $"[AuditQueryResult:{Status}:{Complete}]";
}

/// <summary>Caller-held progress survives cancellation. Indexes refer to the copied input order.</summary>
public sealed class AuditBatchProgress
{
    private readonly AuditQueryResult?[] _results;
    private readonly object _gate = new();
    internal int Used;

    /// <summary>Creates single-use caller-held progress before awaiting a bounded batch.</summary>
    /// <param name="count">The exact input query count, from 1 through 16.</param>
    /// <exception cref="ArgumentOutOfRangeException">The count is outside its supported range.</exception>
    public AuditBatchProgress(int count)
    {
        if (count is < 1 or > 16)
        {
            throw new ArgumentOutOfRangeException(nameof(count));
        }

        _results = new AuditQueryResult?[count];
    }

    /// <summary>Gets the fixed number of input positions.</summary>
    public int Count => _results.Length;
    /// <summary>Gets a synchronized snapshot in input order; null entries have no recorded result yet.</summary>
    [JsonIgnore]
    public IReadOnlyList<AuditQueryResult?> Results
    {
        get
        {
            lock (_gate)
            {
                return Array.AsReadOnly(_results.ToArray());
            }
        }
    }

    internal void Record(int index, AuditQueryResult result)
    {
        lock (_gate)
        {
            _results[index] = result;
        }
    }

    /// <summary>Returns a marker without query results.</summary>
    public override string ToString() => "[AuditBatchProgress]";
}

/// <summary>
/// Separate explicit monitoring credential. Public cloud v1 only; never uses an administrative
/// credential implicitly or grants runtime reads. Clients and transport/credential telemetry are host-owned.
/// </summary>
public sealed class AuditDiagnostics
{
    private readonly TokenCredential _credential;
    private readonly HttpPipelineTransport _transport;
    private readonly int _maximumBytes;
    private readonly TimeProvider _time;

    /// <summary>Borrows an explicitly selected monitoring identity and transport without acquiring credentials.</summary>
    /// <param name="monitoringCredential">Host-owned monitoring credential, independent of administration credentials.</param>
    /// <param name="transport">Host-owned transport; external instrumentation remains the host's responsibility.</param>
    /// <param name="maximumResponseBytes">The local response budget, from 1 KiB through 16 MiB.</param>
    /// <param name="timeProvider">The cooperative deadline clock, or the system clock.</param>
    /// <exception cref="ArgumentNullException">The credential or transport is null.</exception>
    /// <exception cref="ArgumentOutOfRangeException">The response budget is invalid.</exception>
    public AuditDiagnostics(TokenCredential monitoringCredential, HttpPipelineTransport transport,
        int maximumResponseBytes = 1024 * 1024, TimeProvider? timeProvider = null)
    {
        ArgumentNullException.ThrowIfNull(monitoringCredential);
        ArgumentNullException.ThrowIfNull(transport);
        if (maximumResponseBytes is < 1024 or > 16 * 1024 * 1024)
        {
            throw new ArgumentOutOfRangeException(nameof(maximumResponseBytes));
        }

        _credential = monitoringCredential;
        _transport = transport;
        _maximumBytes = maximumResponseBytes;
        _time = timeProvider ?? TimeProvider.System;
    }

    /// <summary>Runs the fixed single-vault audit projection with no retries or arbitrary query input.</summary>
    /// <param name="query">The window, scope and bounds to apply.</param>
    /// <param name="cancellationToken">Cancels acquisition and propagates caller cancellation.</param>
    /// <returns>Copied classified rows and completeness; deadline expiry is an Unavailable result with Deadline error.</returns>
    /// <exception cref="ArgumentNullException">The query is null.</exception>
    /// <exception cref="OperationCanceledException">Caller cancellation was observed.</exception>
    public async ValueTask<AuditQueryResult> QueryAsync(AuditQuery query, CancellationToken cancellationToken = default)
    {
        ArgumentNullException.ThrowIfNull(query);
        cancellationToken.ThrowIfCancellationRequested();
        using var deadline = new CancellationTokenSource(query.Timeout, _time);
        using var linked = CancellationTokenSource.CreateLinkedTokenSource(cancellationToken, deadline.Token);
        var path = query.WorkspaceId is { } workspace
            ? $"/v1/workspaces/{workspace:D}/query" : $"/v1{query.Vault.ResourceId}/query";
        var options = new LogsQueryClientOptions(LogsQueryClientOptions.ServiceVersion.V1)
        {
            Audience = LogsQueryAudience.AzurePublicCloud,
            Transport = new ControlledTransport(_transport, "api.loganalytics.io", path, RequestMethod.Post,
                null, [200], _maximumBytes)
        };
        options.Diagnostics.IsLoggingEnabled = false;
        options.Diagnostics.IsLoggingContentEnabled = false;
        options.Diagnostics.IsDistributedTracingEnabled = false;
        options.Retry.MaxRetries = 0;
        var client = new LogsQueryClient(new Uri("https://api.loganalytics.io"), _credential, options);
        var nativeOptions = new LogsQueryOptions
        {
            ServerTimeout = query.Timeout,
            AllowPartialErrors = true,
            IncludeStatistics = false,
            IncludeVisualization = false
        };
        try
        {
            var range = new QueryTimeRange(query.Start, query.End);
            var response = query.WorkspaceId is { } id
                ? await client.QueryWorkspaceAsync(id.ToString("D"), query.QueryText, range, nativeOptions, linked.Token)
                    .ConfigureAwait(false)
                : await client.QueryResourceAsync(new ResourceIdentifier(query.Vault.ResourceId), query.QueryText,
                    range, nativeOptions, linked.Token).ConfigureAwait(false);
            cancellationToken.ThrowIfCancellationRequested();
            var native = response.Value;
            if (native.Status == LogsQueryResultStatus.Failure)
            {
                return new(SecretStatus.Unknown, [], false, AuditError.QueryFailure);
            }

            if (native.AllTables.Count != 1)
            {
                return new(SecretStatus.Invalid, [], false, AuditError.InvalidResponse);
            }

            var table = native.AllTables[0];
            string[] columns = ["TimeGenerated", "OperationName", "ResultType", "_ResourceId", "Category"];
            if (!table.Columns.Select(c => c.Name).SequenceEqual(columns))
            {
                return new(SecretStatus.Invalid, [], false, AuditError.InvalidResponse);
            }

            var events = new List<AuditEvent>();
            DateTimeOffset? last = null;
            foreach (var row in table.Rows)
            {
                linked.Token.ThrowIfCancellationRequested();
                var timestamp = row.GetDateTimeOffset(0);
                if (row.Count != 5 || timestamp is null || timestamp < query.Start || timestamp >= query.End ||
                    timestamp < last || !row.GetString(3).Equals(query.Vault.ResourceId, StringComparison.OrdinalIgnoreCase) ||
                    row.GetString(4) != "AuditEvent")
                {
                    return new(SecretStatus.Invalid, [], false, AuditError.InvalidResponse);
                }

                last = timestamp;
                var operationText = row.GetString(1);
                var operation = Enum.TryParse<AuditOperation>(operationText, true, out var parsed) && Enum.IsDefined(parsed)
                    ? parsed : AuditOperation.Unknown;
                var result = row.GetString(2) switch
                {
                    "Success" => AuditResultKind.Success,
                    "Failure" => AuditResultKind.Failure,
                    _ => AuditResultKind.Unknown
                };
                if (events.Count < query.MaximumRows)
                {
                    events.Add(new(timestamp.Value, operation, result));
                }
            }

            bool partial = native.Status == LogsQueryResultStatus.PartialFailure || native.Error is not null;
            bool overflow = table.Rows.Count > query.MaximumRows;
            return new(SecretStatus.Success, events, !partial && !overflow,
                partial ? AuditError.PartialFailure : overflow ? AuditError.RowLimit : AuditError.None);
        }
        catch (OperationCanceledException)
        {
            cancellationToken.ThrowIfCancellationRequested();
            return new(SecretStatus.Unavailable, [], false, AuditError.Deadline);
        }
        catch (Exception exception)
        {
            cancellationToken.ThrowIfCancellationRequested();
            return new(ControlledTransport.Failure(exception), [], false, AuditError.QueryFailure);
        }
    }

    /// <summary>Local bounded batch of canonical single queries. Never calls the deprecated /$batch endpoint.</summary>
    /// <param name="queries">One to sixteen queries copied in input order before execution.</param>
    /// <param name="progress">Unused caller-held progress of the same count; completed positions survive cancellation.</param>
    /// <param name="timeout">A one-second to two-minute budget for the whole sequential batch.</param>
    /// <param name="cancellationToken">Cancels the batch; unrecorded positions remain null.</param>
    /// <returns>Completion when each position has a result, including deadline results for unfinished queries.</returns>
    /// <exception cref="ArgumentNullException">Queries or progress is null.</exception>
    /// <exception cref="ArgumentException">The count, budget or progress reuse is invalid.</exception>
    /// <exception cref="OperationCanceledException">Caller cancellation was observed; inspect retained progress.</exception>
    public async ValueTask QueryBatchAsync(IReadOnlyList<AuditQuery> queries, AuditBatchProgress progress,
        TimeSpan timeout, CancellationToken cancellationToken = default)
    {
        ArgumentNullException.ThrowIfNull(queries);
        ArgumentNullException.ThrowIfNull(progress);
        var selected = queries.ToArray();
        if (selected.Length is < 1 or > 16 || selected.Length != progress.Count || selected.Any(q => q is null) ||
            timeout < TimeSpan.FromSeconds(1) || timeout > TimeSpan.FromMinutes(2) ||
            Interlocked.Exchange(ref progress.Used, 1) != 0)
        {
            throw new ArgumentException("Invalid bounded audit batch.");
        }

        using var deadline = new CancellationTokenSource(timeout, _time);
        using var linked = CancellationTokenSource.CreateLinkedTokenSource(cancellationToken, deadline.Token);
        for (int index = 0; index < selected.Length; index++)
        {
            cancellationToken.ThrowIfCancellationRequested();
            if (deadline.IsCancellationRequested)
            {
                progress.Record(index, new AuditQueryResult(SecretStatus.Unavailable, [], false, AuditError.Deadline));
                continue;
            }

            try
            {
                progress.Record(index, await QueryAsync(selected[index], linked.Token).ConfigureAwait(false));
            }
            catch (OperationCanceledException)
            {
                cancellationToken.ThrowIfCancellationRequested();
                progress.Record(index, new AuditQueryResult(SecretStatus.Unavailable, [], false, AuditError.Deadline));
            }
        }
    }
}
