using System.Diagnostics.CodeAnalysis;
using System.Net;
using System.Text;
using System.Text.Json;
using System.Text.Json.Serialization;
using Azure;
using Azure.Core;
using Azure.Core.Pipeline;
using SecretKit.AzureKeyVault.Conformance.Tests.Admission.Management;
using SecretKit.AzureKeyVault.Management;

namespace SecretKit.AzureKeyVault.Conformance.Tests;

public sealed class AzureAuditIngestionCollectorTests
{
    private static readonly DateTimeOffset Start = new(2026, 1, 1, 0, 0, 0, TimeSpan.Zero);
    private static readonly Guid Correlation = Guid.Parse("aaaaaaaa-aaaa-aaaa-aaaa-aaaaaaaaaaaa");
    private static readonly Guid OtherCorrelation = Guid.Parse("bbbbbbbb-bbbb-bbbb-bbbb-bbbbbbbbbbbb");
    private static readonly Guid Workspace = Guid.Parse("cccccccc-cccc-cccc-cccc-cccccccccccc");
    private static VaultScope Vault() => new(new(new(Guid.Parse("11111111-1111-1111-1111-111111111111")), "audit-group"), "audit-vault");
    private static AuditIngestionCollector.Binding Binding(bool workspace = false) =>
        new(new(Guid.NewGuid(), "owned", "audit", "query", "selected"), Guid.NewGuid(), Vault(),
            workspace ? Workspace : null, Start, Start.AddHours(1));

    [Test]
    [Arguments(false)]
    [Arguments(true)]
    public async Task InstalledNativeQueryRetainsActualCorrelationsAndDuplicateMultiplicity(bool workspace)
    {
        using var fixture = new Fixture();
        var binding = Binding(workspace);
        fixture.Backend.Payload = Payload([Row(), Row(OtherCorrelation), Row()]);
        var result = await fixture.Source.CollectAsync(fixture.Source.Arm(binding));
        await Assert.That(result.ResponseComplete).IsTrue();
        await Assert.That(result.Rows.Select(r => r.CorrelationId)).IsEquivalentTo(new Guid?[] { Correlation, OtherCorrelation, Correlation });
        await Assert.That(result.NativeQueryRequestId).IsEqualTo("native-source-query");
        await Assert.That(fixture.Backend.Uri!.AbsoluteUri).IsEqualTo(AuditIngestionCollector.Origin +
            (workspace ? $"/v1/workspaces/{Workspace:D}/query" : "/v1" + Vault().ExportResourceId() + "/query"));
        await Assert.That(fixture.Credential.Scopes.Single()).IsEqualTo("https://api.loganalytics.io//.default");
        await Assert.That(fixture.Backend.Query!.Contains(Vault().ExportResourceId(), StringComparison.Ordinal)).IsTrue();
        await Assert.That(fixture.Backend.Sends).IsEqualTo(1);
        await Assert.That(fixture.Backend.Auth).IsEqualTo("Bearer independent-monitoring");
    }

    [Test]
    [Arguments("SecretGet", AuditOperation.SecretGet)]
    [Arguments("SecretList", AuditOperation.SecretList)]
    [Arguments("SecretSet", AuditOperation.SecretSet)]
    [Arguments("SecretDelete", AuditOperation.SecretDelete)]
    [Arguments("SecretRecover", AuditOperation.SecretRecover)]
    [Arguments("SecretBackup", AuditOperation.SecretBackup)]
    [Arguments("SecretRestore", AuditOperation.SecretRestore)]
    [Arguments("SecretPurge", AuditOperation.SecretPurge)]
    [Arguments("SecretUpdate", AuditOperation.Unknown)]
    [Arguments("SecretListVersions", AuditOperation.Unknown)]
    [Arguments("1", AuditOperation.Unknown)]
    public async Task NativeOperationNamesRemainDistinct(string operation, AuditOperation expected)
    {
        using var fixture = new Fixture();
        fixture.Backend.Payload = Payload([Row(operation: operation)]);
        var result = await fixture.Source.CollectAsync(fixture.Source.Arm(Binding()));
        await Assert.That(result.ResponseComplete).IsTrue();
        await Assert.That(result.Rows.Single().NativeOperation).IsEqualTo(operation);
        await Assert.That(result.Rows.Single().Operation).IsEqualTo(expected);
    }

    [Test]
    [Arguments("partial")]
    [Arguments("overflow")]
    public async Task PartialAndBoundedRowsNeverBecomeComplete(string kind)
    {
        using var fixture = new Fixture(maximumRows: 2);
        fixture.Backend.Payload = Payload(kind == "overflow" ? [Row(), Row(), Row()] : [Row()], partial: kind == "partial");
        var result = await fixture.Source.CollectAsync(fixture.Source.Arm(Binding()));
        await Assert.That(result.ResponseComplete).IsFalse();
        await Assert.That(result.Failure).IsEqualTo(kind == "partial" ? AuditIngestionCollector.Failure.Partial : AuditIngestionCollector.Failure.RowBudget);
        await Assert.That(result.Rows.Count).IsEqualTo(kind == "partial" ? 1 : 2);
        await Assert.That(fixture.Backend.Sends).IsEqualTo(1);
    }

    [Test]
    [Arguments("foreign")]
    [Arguments("category")]
    [Arguments("correlation")]
    [Arguments("end")]
    [Arguments("unordered")]
    [Arguments("missing-column")]
    [Arguments("duplicate-json")]
    [Arguments("extra-table")]
    [Arguments("oversized")]
    [Arguments("request-id")]
    [Arguments("redirect")]
    [Arguments("too-many-rows")]
    public async Task InvalidOrOverBudgetNativeEvidenceCannotEstablishResponseCompleteness(string fault)
    {
        using var fixture = new Fixture(maximumRows: 2);
        object[] row = Row();
        if (fault == "foreign") row[3] = Vault().ExportResourceId().Replace("audit-vault", "other-vault", StringComparison.Ordinal);
        if (fault == "category") row[4] = "Other";
        if (fault == "correlation") row[5] = "not-a-guid";
        if (fault == "end") row[0] = Start.AddHours(1).ToString("O");
        fixture.Backend.Payload = Payload(fault switch
        {
            "unordered" => [Row(timestamp: Start.AddMinutes(2)), Row(timestamp: Start.AddMinutes(1))],
            "too-many-rows" => [Row(), Row(), Row(), Row()],
            _ => [row]
        }, missingColumn: fault == "missing-column", extraTable: fault == "extra-table");
        if (fault == "duplicate-json") fixture.Backend.Payload = """{"tables":[],"tables":[]}""";
        if (fault == "oversized") fixture.Backend.Payload = new string('x', 70000);
        if (fault == "request-id") fixture.Backend.RequestId = null;
        if (fault == "redirect") fixture.Backend.Status = 302;
        var result = await fixture.Source.CollectAsync(fixture.Source.Arm(Binding()));
        await Assert.That(result.ResponseComplete).IsFalse();
        await Assert.That(result.Rows.Count).IsEqualTo(0);
        await Assert.That(fixture.Backend.Sends).IsEqualTo(1);
    }

    [Test]
    [Arguments(403)]
    [Arguments(200)]
    public async Task DenialIsNotTheSameAsAnEmptyVisibleResponse(int status)
    {
        using var fixture = new Fixture();
        fixture.Backend.Status = status;
        fixture.Backend.Payload = status == 200 ? Payload([]) : """{"error":{"code":"Forbidden","message":"private-provider-error"}}""";
        var result = await fixture.Source.CollectAsync(fixture.Source.Arm(Binding()));
        await Assert.That(result.Failure).IsEqualTo(status == 403 ? AuditIngestionCollector.Failure.Denied : AuditIngestionCollector.Failure.None);
        await Assert.That(result.Rows.Count).IsEqualTo(0);
    }

    [Test]
    public async Task EmptyCorrelationIsRetainedAsUnestablishedRatherThanInvented()
    {
        using var fixture = new Fixture();
        object[] row = Row();
        row[5] = "";
        fixture.Backend.Payload = Payload([row]);
        var result = await fixture.Source.CollectAsync(fixture.Source.Arm(Binding()));
        await Assert.That(result.Rows.Single().CorrelationId).IsNull();
        await Assert.That(JsonSerializer.Serialize(result)).IsEqualTo("{}");
        await Assert.That(JsonSerializer.Serialize(result.Rows[0]).Contains(Correlation.ToString(), StringComparison.Ordinal)).IsFalse();
    }

    [Test]
    public async Task WideRawRowsAreRejectedBeforeSdkFacingStreamReplacement()
    {
        using var fixture = new Fixture();
        object[] wide = [.. Row(), .. Enumerable.Repeat<object>("", 10000)];
        fixture.Backend.Payload = Payload([wide]);
        var result = await fixture.Source.CollectAsync(fixture.Source.Arm(Binding()));
        await Assert.That(result.Failure).IsEqualTo(AuditIngestionCollector.Failure.Boundary);
        await Assert.That(result.Rows.Count).IsEqualTo(0);
        await Assert.That(fixture.Tracking.Replacements).IsEqualTo(0);
    }

    [Test]
    [Arguments(false)]
    [Arguments(true)]
    public async Task ResponseReadDrainsAndClearsOwnedStorageOnSuccessAndCancellation(bool cancel)
    {
        using var fixture = new Fixture();
        using var content = new ObservedReadStream(Encoding.UTF8.GetBytes(Payload([Row()])), cancel);
        fixture.Backend.Body = content;
        using var cancellation = new CancellationTokenSource();
        var collection = fixture.Source.CollectAsync(fixture.Source.Arm(Binding()), cancellation.Token).AsTask();
        if (cancel)
        {
            await Task.WhenAny(content.Blocked.Task, collection).WaitAsync(TimeSpan.FromSeconds(10));
            if (collection.IsCompleted) await collection;
            await content.Blocked.Task.WaitAsync(TimeSpan.FromSeconds(10));
            await Assert.That(content.Destination.Span.IndexOfAnyExcept((byte)0) >= 0).IsTrue();
            cancellation.Cancel();
            await Assert.That(async () => await collection).Throws<OperationCanceledException>();
        }
        else await Assert.That((await collection).ResponseComplete).IsTrue();
        await Assert.That(content.Disposed).IsTrue();
        await Assert.That(content.Destination.Length > 0).IsTrue();
        await Assert.That(content.Destination.Span.IndexOfAnyExcept((byte)0)).IsEqualTo(-1);
        await Assert.That(fixture.Backend.Sends).IsEqualTo(1);
    }

    [Test]
    public async Task InjectedDeadlineTerminatesTheSingleNativeRequestWithoutRetry()
    {
        var clock = new DeadlineClock();
        using var fixture = new Fixture(clock: clock);
        fixture.Backend.Block = true;
        fixture.Backend.Entered = new(TaskCreationOptions.RunContinuationsAsynchronously);
        var collection = fixture.Source.CollectAsync(fixture.Source.Arm(Binding())).AsTask();
        await Task.WhenAny(fixture.Backend.Entered.Task, collection).WaitAsync(TimeSpan.FromSeconds(10));
        if (collection.IsCompleted) await collection;
        await fixture.Backend.Entered.Task.WaitAsync(TimeSpan.FromSeconds(10));
        clock.Expire();
        var result = await collection;
        await Assert.That(result.Failure).IsEqualTo(AuditIngestionCollector.Failure.Deadline);
        await Assert.That(result.ResponseComplete).IsFalse();
        await Assert.That(fixture.Backend.Terminated).IsTrue();
        await Assert.That(fixture.Backend.Sends).IsEqualTo(1);
    }

    [Test]
    public async Task WindowsAreSourceOwnedSingleUseAndCancellationDrainsTheNativeRequest()
    {
        using var fixture = new Fixture();
        using var other = new Fixture();
        var window = fixture.Source.Arm(Binding());
        await Assert.That(async () => await other.Source.CollectAsync(window)).Throws<InvalidOperationException>();
        fixture.Backend.Entered = new(TaskCreationOptions.RunContinuationsAsynchronously);
        fixture.Backend.Block = true;
        using var cancellation = new CancellationTokenSource();
        var collection = fixture.Source.CollectAsync(window, cancellation.Token).AsTask();
        await Task.WhenAny(fixture.Backend.Entered.Task, collection).WaitAsync(TimeSpan.FromSeconds(10));
        if (collection.IsCompleted) await collection;
        await fixture.Backend.Entered.Task.WaitAsync(TimeSpan.FromSeconds(10));
        cancellation.Cancel();
        await Assert.That(async () => await collection).Throws<OperationCanceledException>();
        await Assert.That(fixture.Backend.Terminated).IsTrue();
        await Assert.That(async () => await fixture.Source.CollectAsync(window)).Throws<InvalidOperationException>();
        await Assert.That(fixture.Backend.Sends).IsEqualTo(1);
        await Assert.That(fixture.Backend.Disposed).IsFalse();
    }

    private static object[] Row(Guid? correlation = null, string operation = "SecretSet", DateTimeOffset? timestamp = null) =>
        [(timestamp ?? Start).ToString("O"), operation, "Success", Vault().ExportResourceId(), "AuditEvent", (correlation ?? Correlation).ToString("D")];
    private static string Payload(object[][] rows, bool partial = false, bool missingColumn = false, bool extraTable = false)
    {
        var table = new
        {
            name = "PrimaryResult",
            columns = new[] { "TimeGenerated", "OperationName", "ResultType", "_ResourceId", "Category", "CorrelationId" }
                .Take(missingColumn ? 5 : 6).Select((name, i) => new { name, type = i == 0 ? "datetime" : "string" }).ToArray(),
            rows = rows.Select(r => missingColumn ? r.Take(5).ToArray() : r).ToArray()
        };
        return JsonSerializer.Serialize(new
        {
            tables = extraTable ? new[] { table, table } : [table],
            error = partial ? new
            {
                code = "PartialError",
                message = "private-query-error",
                details = new[] { new { code = "LimitsExceeded", message = "private-detail" } }
            } : null
        }, new JsonSerializerOptions { DefaultIgnoreCondition = JsonIgnoreCondition.WhenWritingNull });
    }
    private sealed class Fixture : IDisposable
    {
        internal readonly Backend Backend = new();
        internal readonly Credential Credential = new();
        private readonly HttpClient http;
        internal readonly TrackingTransport Tracking;
        internal readonly AuditIngestionCollector Source;
        internal Fixture(int maximumRows = 10, TimeProvider? clock = null)
        {
            http = new(Backend);
            Tracking = new(new HttpClientTransport(http));
            Source = new(Credential, Tracking, new(maximumRows, 65536, TimeSpan.FromSeconds(10)), clock);
        }
        public void Dispose() => http.Dispose();
    }
    private sealed class ObservedReadStream(byte[] bytes, bool block) : MemoryStream(bytes)
    {
        internal Memory<byte> Destination { get; private set; }
        internal bool Disposed;
        internal readonly TaskCompletionSource Blocked = new(TaskCreationOptions.RunContinuationsAsynchronously);
        public override async ValueTask<int> ReadAsync(Memory<byte> buffer, CancellationToken cancellationToken = default)
        {
            if (Destination.Length == 0) Destination = buffer;
            if (block && Position != 0)
            {
                var stopped = new TaskCompletionSource(TaskCreationOptions.RunContinuationsAsynchronously);
                using var registration = cancellationToken.Register(() => stopped.TrySetResult());
                Blocked.TrySetResult();
                await stopped.Task;
                cancellationToken.ThrowIfCancellationRequested();
            }
            return await base.ReadAsync(buffer, cancellationToken);
        }
        protected override void Dispose(bool disposing) { Disposed = true; base.Dispose(disposing); }
    }
    private sealed class TrackingTransport(HttpPipelineTransport inner) : HttpPipelineTransport
    {
        internal int Replacements;
        public override Request CreateRequest() => inner.CreateRequest();
        public override void Process(HttpMessage message) => throw new InvalidOperationException("test-sync");
        public override async ValueTask ProcessAsync(HttpMessage message)
        {
            await inner.ProcessAsync(message);
            message.Response = new TrackedResponse(message.Response, () => Replacements++);
        }
        private sealed class TrackedResponse(Response inner, Action replaced) : Response
        {
            public override int Status => inner.Status;
            public override string ReasonPhrase => inner.ReasonPhrase;
            public override string ClientRequestId { get => inner.ClientRequestId; set => inner.ClientRequestId = value; }
            public override Stream? ContentStream
            {
                get => inner.ContentStream;
                set { replaced(); inner.ContentStream = value; }
            }
            public override void Dispose() => inner.Dispose();
            protected override bool ContainsHeader(string name) => inner.Headers.Contains(name);
            protected override IEnumerable<HttpHeader> EnumerateHeaders() => inner.Headers;
            protected override bool TryGetHeader(string name, [NotNullWhen(true)] out string? value) => inner.Headers.TryGetValue(name, out value);
            protected override bool TryGetHeaderValues(string name, [NotNullWhen(true)] out IEnumerable<string>? values) => inner.Headers.TryGetValues(name, out values);
        }
    }
    private sealed class DeadlineClock : TimeProvider
    {
        private Hook? hook;
        public override ITimer CreateTimer(TimerCallback callback, object? state, TimeSpan dueTime, TimeSpan period) =>
            hook = new Hook(callback, state);
        internal void Expire() => hook!.Fire();
        private sealed class Hook(TimerCallback callback, object? state) : ITimer
        {
            private bool disposed;
            internal void Fire() { if (!disposed) callback(state); }
            public bool Change(TimeSpan dueTime, TimeSpan period) => !disposed;
            public void Dispose() => disposed = true;
            public ValueTask DisposeAsync() { Dispose(); return ValueTask.CompletedTask; }
        }
    }
    private sealed class Credential : TokenCredential
    {
        internal readonly List<string> Scopes = [];
        public override AccessToken GetToken(TokenRequestContext context, CancellationToken cancellationToken)
        {
            Scopes.AddRange(context.Scopes);
            return new("independent-monitoring", DateTimeOffset.MaxValue);
        }
        public override ValueTask<AccessToken> GetTokenAsync(TokenRequestContext context, CancellationToken cancellationToken) =>
            ValueTask.FromResult(GetToken(context, cancellationToken));
    }
    private sealed class Backend : HttpMessageHandler
    {
        internal string Payload = AzureAuditIngestionCollectorTests.Payload([Row()]);
        internal int Status = 200, Sends;
        internal string? RequestId = "native-source-query", Query, Auth;
        internal Uri? Uri;
        internal bool Block, Terminated, Disposed;
        internal TaskCompletionSource? Entered;
        internal Stream? Body;
        protected override async Task<HttpResponseMessage> SendAsync(HttpRequestMessage request, CancellationToken token)
        {
            Sends++;
            Uri = request.RequestUri;
            Auth = request.Headers.Authorization?.ToString();
            using var body = JsonDocument.Parse(await request.Content!.ReadAsStringAsync(token));
            Query = body.RootElement.GetProperty("query").GetString();
            if (Block)
            {
                var stopped = new TaskCompletionSource(TaskCreationOptions.RunContinuationsAsynchronously);
                using var registration = token.Register(() => stopped.TrySetResult());
                Entered?.TrySetResult();
                await stopped.Task;
                Terminated = true;
                token.ThrowIfCancellationRequested();
            }
            var response = new HttpResponseMessage((HttpStatusCode)Status)
            {
                Content = Body is null ? new StringContent(Payload) : new StreamContent(Body)
            };
            if (RequestId is not null) response.Headers.Add("x-ms-request-id", RequestId);
            return response;
        }
        protected override void Dispose(bool disposing) { Disposed = true; base.Dispose(disposing); }
    }
}
