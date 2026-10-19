using System.Globalization;
using System.Security.Cryptography;
using System.Text.Json;
using System.Text.Json.Serialization;
using Azure.Core;
using Azure.Core.Pipeline;
using Azure.Monitor.Query;
using Azure.Monitor.Query.Models;
using SecretKit.AzureKeyVault.Management;

namespace SecretKit.AzureKeyVault.Conformance.Tests.Admission.Management;

// Independent, read-only native query source. Response completeness is not an
// ingestion watermark. Raw correlation IDs require separately captured native
// request evidence before a service can establish trigger causality.
internal sealed class AuditIngestionCollector
{
    // The pinned 1.7.1 SDK binds AzurePublicCloud to this endpoint. The newer
    // documented azure.com endpoint is not a silent migration of that contract.
    internal const string Origin = "https://api.loganalytics.io";
    internal enum Failure { None, Denied, Query, Partial, RowBudget, Boundary, Deadline, Unavailable }
    internal sealed record Limits(int MaximumRows, int MaximumResponseBytes, TimeSpan Timeout);
    internal sealed record Binding([property: JsonIgnore] FixtureSelector Selector,
        [property: JsonIgnore] Guid LeaseId, [property: JsonIgnore] VaultScope Vault,
        [property: JsonIgnore] Guid? WorkspaceId, DateTimeOffset Start, DateTimeOffset End)
    {
        public override string ToString() => "[AuditCollectionBinding]";
    }
    internal sealed record Row(DateTimeOffset Timestamp, AuditOperation Operation, AuditResultKind Result,
        [property: JsonIgnore] string NativeOperation, [property: JsonIgnore] Guid? CorrelationId)
    {
        public override string ToString() => "[AuditCollectionRow]";
    }
    internal sealed class Window(object owner, Binding binding)
    {
        internal object Owner { get; } = owner;
        internal Binding Binding { get; } = binding;
        internal int Consumed;
        public override string ToString() => "[AuditCollectionWindow]";
    }
    internal sealed class Measurement
    {
        internal required Binding Binding { get; init; }
        internal required Failure Failure { get; init; }
        internal required IReadOnlyList<Row> Rows { get; init; }
        internal required string? NativeQueryRequestId { get; init; }
        internal bool ResponseComplete => Failure == Failure.None;
        public override string ToString() => "[AuditCollectionMeasurement]";
    }

    private readonly TokenCredential credential;
    private readonly HttpPipelineTransport transport;
    private readonly Limits limits;
    private readonly TimeProvider time;
    private readonly object owner = new();

    internal AuditIngestionCollector(TokenCredential credential, HttpPipelineTransport transport, Limits limits,
        TimeProvider? time = null)
    {
        if (credential is null || transport is null || limits is null || limits.MaximumRows is < 1 or > 1000 ||
            limits.MaximumResponseBytes is < 1024 or > 16 * 1024 * 1024 ||
            limits.Timeout < TimeSpan.FromSeconds(1) || limits.Timeout > TimeSpan.FromMinutes(2))
            throw new ArgumentException("audit-collector-input");
        this.credential = credential;
        this.transport = transport;
        this.limits = limits;
        this.time = time ?? TimeProvider.System;
    }

    internal Window Arm(Binding binding)
    {
        if (binding is null || binding.Vault is null || binding.LeaseId == Guid.Empty ||
            binding.Selector is null || binding.Selector.Nonce == Guid.Empty ||
            new[] { binding.Selector.Operation, binding.Selector.Variant, binding.Selector.Case, binding.Selector.Scope }
                .Any(s => string.IsNullOrWhiteSpace(s) || s.Length > 1024) ||
            binding.WorkspaceId == Guid.Empty || binding.End <= binding.Start ||
            binding.End - binding.Start > TimeSpan.FromDays(1))
            throw new ArgumentException("audit-collector-binding");
        return new(owner, binding);
    }

    internal async ValueTask<Measurement> CollectAsync(Window window, CancellationToken cancellationToken = default)
    {
        cancellationToken.ThrowIfCancellationRequested();
        if (window is null || !ReferenceEquals(window.Owner, owner) ||
            Interlocked.Exchange(ref window.Consumed, 1) != 0)
            throw new InvalidOperationException("audit-collector-window");
        Binding binding = window.Binding;
        using var deadline = new CancellationTokenSource(limits.Timeout, time);
        using var linked = CancellationTokenSource.CreateLinkedTokenSource(cancellationToken, deadline.Token);
        string resource = binding.Vault.ExportResourceId();
        string path = binding.WorkspaceId is { } workspace ? $"/v1/workspaces/{workspace:D}/query" : "/v1" + resource + "/query";
        using var boundary = new QueryTransport(transport, path, limits);
        var options = new LogsQueryClientOptions(LogsQueryClientOptions.ServiceVersion.V1)
        {
            Audience = LogsQueryAudience.AzurePublicCloud,
            Transport = boundary
        };
        options.Retry.MaxRetries = 0;
        options.Diagnostics.IsLoggingEnabled = false;
        options.Diagnostics.IsLoggingContentEnabled = false;
        options.Diagnostics.IsDistributedTracingEnabled = false;
        var client = new LogsQueryClient(new Uri(Origin), credential, options);
        string query = "AzureDiagnostics | where ResourceProvider == 'MICROSOFT.KEYVAULT' and Category == 'AuditEvent' " +
            $"and _ResourceId =~ '{resource}' | where TimeGenerated >= datetime({binding.Start.UtcDateTime.ToString("O", CultureInfo.InvariantCulture)}) " +
            $"and TimeGenerated < datetime({binding.End.UtcDateTime.ToString("O", CultureInfo.InvariantCulture)}) " +
            "| project TimeGenerated, OperationName, ResultType, _ResourceId, Category, CorrelationId = tostring(column_ifexists('CorrelationId', '')) " +
            $"| order by TimeGenerated asc, OperationName asc, ResultType asc, CorrelationId asc | take {limits.MaximumRows + 1}";
        try
        {
            var nativeOptions = new LogsQueryOptions
            {
                ServerTimeout = limits.Timeout,
                AllowPartialErrors = true,
                IncludeStatistics = false,
                IncludeVisualization = false
            };
            var range = new QueryTimeRange(binding.Start, binding.End);
            var response = binding.WorkspaceId is { } id
                ? await client.QueryWorkspaceAsync(id.ToString("D"), query, range, nativeOptions, linked.Token).ConfigureAwait(false)
                : await client.QueryResourceAsync(new ResourceIdentifier(resource), query, range, nativeOptions, linked.Token).ConfigureAwait(false);
            using var raw = response.GetRawResponse();
            linked.Token.ThrowIfCancellationRequested();
            var result = response.Value;
            if (result.Status == LogsQueryResultStatus.Failure) return Finish(Failure.Query);
            Require(result.Status == LogsQueryResultStatus.Success || result.Status == LogsQueryResultStatus.PartialFailure);
            Require(result.AllTables.Count == 1);
            var table = result.AllTables[0];
            Require(table.Columns.Select(c => c.Name).SequenceEqual(
                new[] { "TimeGenerated", "OperationName", "ResultType", "_ResourceId", "Category", "CorrelationId" }));
            var rows = new List<Row>();
            DateTimeOffset? last = null;
            foreach (var row in table.Rows)
            {
                linked.Token.ThrowIfCancellationRequested();
                Require(row.Count == 6);
                DateTimeOffset? timestamp = row.GetDateTimeOffset(0);
                Require(timestamp is not null && timestamp >= binding.Start && timestamp < binding.End && timestamp >= (last ?? binding.Start) &&
                    string.Equals(row.GetString(3), resource, StringComparison.OrdinalIgnoreCase) && row.GetString(4) == "AuditEvent");
                last = timestamp;
                string operation = row.GetString(1), correlation = row.GetString(5);
                Require(operation.Length is > 0 and <= 128 && !operation.Any(char.IsControl));
                Guid? correlationId = null;
                if (correlation.Length != 0)
                {
                    Require(Guid.TryParse(correlation, out var parsedId) && parsedId != Guid.Empty);
                    correlationId = parsedId;
                }
                AuditOperation projected = Enum.TryParse<AuditOperation>(operation, true, out var parsed) && Enum.IsDefined(parsed) &&
                    parsed.ToString().Equals(operation, StringComparison.OrdinalIgnoreCase)
                    ? parsed : AuditOperation.Unknown;
                AuditResultKind resultKind = row.GetString(2) switch
                {
                    "Success" => AuditResultKind.Success,
                    "Failure" => AuditResultKind.Failure,
                    _ => AuditResultKind.Unknown
                };
                if (rows.Count < limits.MaximumRows) rows.Add(new(timestamp!.Value, projected, resultKind, operation, correlationId));
            }
            bool partial = result.Status == LogsQueryResultStatus.PartialFailure || result.Error is not null;
            return Finish(partial ? Failure.Partial : table.Rows.Count > limits.MaximumRows ? Failure.RowBudget : Failure.None, rows);
        }
        catch (OperationCanceledException)
        {
            cancellationToken.ThrowIfCancellationRequested();
            return Finish(Failure.Deadline);
        }
        catch (Exception)
        {
            cancellationToken.ThrowIfCancellationRequested();
            return Finish(deadline.IsCancellationRequested ? Failure.Deadline :
                boundary.Status is 401 or 403 ? Failure.Denied : boundary.Status == 200 ? Failure.Boundary : Failure.Unavailable);
        }

        Measurement Finish(Failure failure, List<Row>? rows = null) => new()
        {
            Binding = binding,
            Failure = failure,
            Rows = (rows ?? []).AsReadOnly(),
            NativeQueryRequestId = boundary.RequestId
        };
    }

    private static void Require(bool condition)
    {
        if (!condition) throw new InvalidOperationException("audit-collector-boundary");
    }

    private sealed class QueryTransport(HttpPipelineTransport inner, string path, Limits limits) : HttpPipelineTransport, IDisposable
    {
        private int sends;
        private byte[]? storage;
        private MemoryStream? buffer;
        private Azure.Response? response;
        internal int? Status { get; private set; }
        internal string? RequestId { get; private set; }
        public override Request CreateRequest() => inner.CreateRequest();
        public override void Process(HttpMessage message) => throw new InvalidOperationException("audit-collector-sync");
        public override async ValueTask ProcessAsync(HttpMessage message)
        {
            message.CancellationToken.ThrowIfCancellationRequested();
            Uri uri = message.Request.Uri.ToUri();
            Require(++sends == 1 && uri.Scheme == "https" && uri.IsDefaultPort && uri.UserInfo.Length == 0 &&
                uri.Fragment.Length == 0 && uri.GetLeftPart(UriPartial.Authority) == Origin &&
                uri.AbsolutePath.Equals(path, StringComparison.OrdinalIgnoreCase) && uri.Query.Length == 0 &&
                message.Request.Method == RequestMethod.Post && message.Request.Content is not null);
            message.BufferResponse = false;
            await inner.ProcessAsync(message).ConfigureAwait(false);
            response = message.Response;
            Status = response.Status;
            if (Status != 200) throw new InvalidOperationException("audit-collector-response");
            try
            {
                if (!message.Response.Headers.TryGetValues("x-ms-request-id", out var ids))
                    throw new InvalidOperationException("audit-collector-request-id");
                string[] values = ids.ToArray();
                Require(values.Length == 1 && values[0].Length is > 0 and <= 256 &&
                    values[0].All(c => char.IsAsciiLetterOrDigit(c) || c is '-' or '_' or '.'));
                RequestId = values[0];
                long? declared = null;
                if (message.Response.Headers.TryGetValues("Content-Length", out var lengths))
                {
                    string[] raw = lengths.ToArray();
                    if (raw.Length != 1 || !long.TryParse(raw[0], NumberStyles.None, CultureInfo.InvariantCulture, out long length) ||
                        length < 0 || length > limits.MaximumResponseBytes)
                        throw new InvalidOperationException("audit-collector-length");
                    declared = length;
                }
                storage = new byte[limits.MaximumResponseBytes + 1];
                int count = 0;
                if (message.Response.ContentStream is { } source)
                {
                    using (source)
                    {
                        int read;
                        while ((read = await source.ReadAsync(storage.AsMemory(count), message.CancellationToken).ConfigureAwait(false)) != 0)
                        {
                            count += read;
                            Require(count <= limits.MaximumResponseBytes);
                        }
                    }
                }
                Require(declared is null || declared == count);
                using var document = JsonDocument.Parse(storage.AsMemory(0, count), new JsonDocumentOptions { MaxDepth = 32 });
                Unique(document.RootElement);
                var tables = document.RootElement.GetProperty("tables");
                Require(tables.ValueKind == JsonValueKind.Array && tables.GetArrayLength() == 1);
                var rows = tables[0].GetProperty("rows");
                Require(rows.ValueKind == JsonValueKind.Array && rows.GetArrayLength() <= limits.MaximumRows + 1);
                Require(tables[0].GetProperty("columns").GetArrayLength() == 6);
                foreach (var row in rows.EnumerateArray())
                    Require(row.ValueKind == JsonValueKind.Array && row.GetArrayLength() == 6 &&
                        row.EnumerateArray().All(cell => cell.ValueKind == JsonValueKind.String));
                buffer = new MemoryStream(storage, 0, count, writable: false);
                message.Response.ContentStream = buffer;
                message.CancellationToken.ThrowIfCancellationRequested();
            }
            catch
            {
                message.Response.Dispose();
                throw;
            }
        }
        private static void Unique(JsonElement node)
        {
            if (node.ValueKind == JsonValueKind.Object)
            {
                var names = new HashSet<string>(StringComparer.OrdinalIgnoreCase);
                foreach (var property in node.EnumerateObject()) { Require(names.Add(property.Name)); Unique(property.Value); }
            }
            else if (node.ValueKind == JsonValueKind.Array)
                foreach (var value in node.EnumerateArray()) Unique(value);
        }
        public void Dispose()
        {
            buffer?.Dispose();
            if (storage is not null) CryptographicOperations.ZeroMemory(storage);
            response?.Dispose();
        }
    }

    public override string ToString() => "[AuditIngestionCollector]";
}
