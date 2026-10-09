using System.Globalization;
using System.Text.Json.Serialization;
using Azure.Core;
using Azure.Core.Pipeline;
using Azure.Monitor.Query;
using Azure.Monitor.Query.Models;
using SecretKit.Core;

namespace SecretKit.AzureKeyVault.Management;

public enum AuditOperation { Unknown, SecretGet, SecretList, SecretSet, SecretDelete, SecretRecover, SecretBackup, SecretRestore, SecretPurge }
public enum AuditResultKind { Unknown, Success, Failure }
public enum AuditError { None, PartialFailure, QueryFailure, InvalidResponse, RowLimit, Deadline }

/// <summary>
/// One bounded AzureDiagnostics AuditEvent window for exactly one vault. There is no raw KQL,
/// additional workspace, arbitrary column selection, cross-resource query or synthetic cursor.
/// </summary>
public sealed class AuditQuery
{
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

    [JsonIgnore]
    public VaultScope Vault { get; }
    public DateTimeOffset Start { get; }
    public DateTimeOffset End { get; }
    public int MaximumRows { get; }
    public int MaximumPages => 1;
    public TimeSpan Timeout { get; }
    [JsonIgnore]
    public Guid? WorkspaceId { get; }

    internal string QueryText =>
        $"AzureDiagnostics | where ResourceProvider == 'MICROSOFT.KEYVAULT' and Category == 'AuditEvent' " +
        $"and _ResourceId =~ '{Vault.ResourceId}' " +
        $"| where TimeGenerated >= datetime({Start.UtcDateTime.ToString("O", CultureInfo.InvariantCulture)}) " +
        $"and TimeGenerated < datetime({End.UtcDateTime.ToString("O", CultureInfo.InvariantCulture)}) " +
        $"| project TimeGenerated, OperationName, ResultType, _ResourceId, Category " +
        $"| order by TimeGenerated asc, OperationName asc, ResultType asc | take {MaximumRows + 1}";

    public override string ToString() => "[AuditQuery]";
}

public sealed class AuditEvent(DateTimeOffset timestamp, AuditOperation operation, AuditResultKind result)
{
    public DateTimeOffset Timestamp { get; } = timestamp;
    public AuditOperation Operation { get; } = operation;
    public AuditResultKind Result { get; } = result;
    public override string ToString() => "[AuditEvent]";
}

public sealed class AuditQueryResult
{
    internal AuditQueryResult(SecretStatus status, IReadOnlyList<AuditEvent> events, bool complete, AuditError error)
    {
        Status = status;
        Events = Array.AsReadOnly(events.ToArray());
        Complete = complete;
        Error = error;
    }

    public SecretStatus Status { get; }
    [JsonIgnore]
    public IReadOnlyList<AuditEvent> Events { get; }
    public bool Complete { get; }
    public AuditError Error { get; }
    public int Pages => Status == SecretStatus.Success ? 1 : 0;
    public bool RuntimeDeliveryProven => false;
    public override string ToString() => $"[AuditQueryResult:{Status}:{Complete}]";
}

/// <summary>Caller-held progress survives cancellation. Indexes refer to the copied input order.</summary>
public sealed class AuditBatchProgress
{
    private readonly AuditQueryResult?[] _results;
    private readonly object _gate = new();
    internal int Used;

    public AuditBatchProgress(int count)
    {
        if (count is < 1 or > 16)
        {
            throw new ArgumentOutOfRangeException(nameof(count));
        }

        _results = new AuditQueryResult?[count];
    }

    public int Count => _results.Length;
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
