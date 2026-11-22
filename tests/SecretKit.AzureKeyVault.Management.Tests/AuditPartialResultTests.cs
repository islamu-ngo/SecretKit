using System.Text.Json;
using Azure.Core;
using Azure.Monitor.Query.Logs;
using SecretKit.Core;

namespace SecretKit.AzureKeyVault.Management.Tests;

public sealed class AuditPartialResultTests
{
    [Test]
    [Arguments(false)]
    [Arguments(true)]
    public async Task EmptyAuditResultsCannotPublishAfterTheDeadline(bool expiresAtEof)
    {
        var clock = new CompletionClock();
        byte[] body = System.Text.Encoding.UTF8.GetBytes(Rows(ScopeAuthorityTests.Id, count: 0));
        var backend = new WireBackend((_, _) => Task.FromResult(
            new HttpResponseMessage(System.Net.HttpStatusCode.OK)
            {
                Content = new StreamContent(new EndSignalStream(body,
                    () => { if (expiresAtEof) clock.Expire(); }))
            }));
        var client = new AuditDiagnostics(new Credential(), backend, timeProvider: clock);

        var result = await client.QueryAsync(Query());

        await Assert.That(result.Status).IsEqualTo(expiresAtEof ? SecretStatus.Unavailable : SecretStatus.Success);
        await Assert.That(result.Complete).IsEqualTo(!expiresAtEof);
        await Assert.That(result.Events).IsEmpty();
        if (expiresAtEof) await Assert.That(result.Error).IsEqualTo(AuditError.Deadline);
    }

    private static readonly DateTimeOffset Start = DateTimeOffset.Parse("2026-01-01T00:00:00Z");
    private static AuditQuery Query(Guid? workspace = null, int rows = 10) =>
        new(ScopeAuthorityTests.Scope(), Start, Start.AddHours(1), rows, workspaceId: workspace);

    private static string Rows(string id, int count = 1, bool partial = false, bool extraColumn = false) =>
        JsonSerializer.Serialize(new
        {
            tables = new[]
            {
                new
                {
                    name = "PrimaryResult",
                    columns = new[]
                    {
                        new { name = "TimeGenerated", type = "datetime" },
                        new { name = "OperationName", type = "string" },
                        new { name = "ResultType", type = "string" },
                        new { name = "_ResourceId", type = "string" },
                        new { name = "Category", type = "string" }
                    }.Concat(extraColumn ? [new { name = "CallerIpAddress", type = "string" }] : []).ToArray(),
                    rows = Enumerable.Range(0, count).Select(index =>
                        new object[] { Start.AddMinutes(index).ToString("O"), "SecretGet", "Success", id, "AuditEvent" }
                            .Concat(extraColumn ? ["audit-column-canary"] : []).ToArray()).ToArray()
                }
            },
            error = partial ? new
            {
                code = "PartialError",
                message = "sensitive-error-canary",
                details = new[] { new { code = "LimitsExceeded", message = "sensitive-detail-canary" } }
            } : null
        }, new JsonSerializerOptions { DefaultIgnoreCondition = System.Text.Json.Serialization.JsonIgnoreCondition.WhenWritingNull });

    [Test]
    [Arguments(-2)]
    [Arguments(-1)]
    [Arguments(0)]
    [Arguments(1)]
    [Arguments(2)]
    [Arguments(3)]
    [Arguments(4)]
    public async Task InvalidOverflowRowDiscardsTheWholeProjection(int fault)
    {
        var body = System.Text.Json.Nodes.JsonNode.Parse(Rows(ScopeAuthorityTests.Id, 2))!;
        var rows = body["tables"]![0]!["rows"]!.AsArray();
        var row = rows[1]!.AsArray();
        if (fault == -2) row.Clear();
        else if (fault == -1) row.RemoveAt(4);
        else row[fault] = null;
        var backend = new WireBackend((_, _) => Task.FromResult(WireBackend.Json(200, body.ToJsonString())));
        var result = await new AuditDiagnostics(new Credential(), backend).QueryAsync(Query(rows: 1));
        await Assert.That(result.Error).IsEqualTo(AuditError.InvalidResponse);
        await Assert.That(result.Status).IsEqualTo(SecretStatus.Invalid);
        await Assert.That(result.Events.Count).IsEqualTo(0);
        await Assert.That(result.Complete).IsFalse();
    }

    [Test]
    [Arguments("1", AuditOperation.Unknown)]
    [Arguments("seCREtGET", AuditOperation.SecretGet)]
    public async Task OnlyNamedOperationsAreRecognized(string name, AuditOperation expected)
    {
        var backend = new WireBackend((_, _) => Task.FromResult(WireBackend.Json(200,
            Rows(ScopeAuthorityTests.Id).Replace("SecretGet", name, StringComparison.Ordinal))));
        var result = await new AuditDiagnostics(new Credential(), backend).QueryAsync(Query());
        await Assert.That(result.Events.Single().Operation).IsEqualTo(expected);
    }

    [Test]
    [Arguments(false, AuditCloud.Public)]
    [Arguments(true, AuditCloud.Public)]
    [Arguments(false, AuditCloud.USGovernment)]
    [Arguments(true, AuditCloud.USGovernment)]
    [Arguments(false, AuditCloud.China)]
    [Arguments(true, AuditCloud.China)]
    public async Task QueryUsesOnlySelectedMonitoringIdentityAndCanonicalSinglePost(bool workspace, AuditCloud cloud)
    {
        var administrative = new Credential();
        var monitoring = new Credential();
        var workspaceId = Guid.Parse("44444444-4444-4444-4444-444444444444");
        var descriptor = cloud switch
        {
            AuditCloud.Public => LogsQueryAudience.AzurePublicCloud,
            AuditCloud.USGovernment => LogsQueryAudience.AzureGovernment,
            AuditCloud.China => LogsQueryAudience.AzureChina,
            _ => throw new ArgumentOutOfRangeException(nameof(cloud))
        };
        Uri? directUri = null;
        var directCredential = new Credential();
        var directClient = new LogsQueryClient(directCredential, new LogsQueryClientOptions
        {
            Audience = descriptor,
            Diagnostics =
            {
                IsLoggingEnabled = false,
                IsLoggingContentEnabled = false,
                IsDistributedTracingEnabled = false
            },
            Transport = new WireBackend((request, _) =>
            {
                directUri = request.RequestUri;
                return Task.FromResult(WireBackend.Json(200, Rows(ScopeAuthorityTests.Id)));
            })
        });
        var range = new LogsQueryTimeRange(Start, Start.AddHours(1));
        if (workspace) await directClient.QueryWorkspaceAsync(workspaceId.ToString("D"), "AzureDiagnostics", range);
        else await directClient.QueryResourceAsync(new ResourceIdentifier(ScopeAuthorityTests.Id), "AzureDiagnostics", range);
        await Assert.That(directUri!.GetLeftPart(UriPartial.Authority)).IsEqualTo(directClient.Endpoint.GetLeftPart(UriPartial.Authority));
        await Assert.That(directCredential.Audiences.Single()).IsEqualTo(descriptor.ToString().TrimEnd('/') + "/.default");
        bool queryScoped = false;
        var backend = new WireBackend(async (request, token) =>
        {
            if (request.RequestUri != directUri || request.Method != HttpMethod.Post ||
                request.RequestUri!.AbsolutePath != (workspace ? $"/v1/workspaces/{workspaceId:D}/query" :
                    $"/v1{ScopeAuthorityTests.Id}/query"))
            {
                throw new InvalidOperationException("Wrong monitoring route.");
            }

            using var body = JsonDocument.Parse(await request.Content!.ReadAsStringAsync(token));
            var text = body.RootElement.GetProperty("query").GetString()!;
            queryScoped = (text.Contains($"_ResourceId =~ '{ScopeAuthorityTests.Id}'", StringComparison.Ordinal) ||
                text.Contains($"_ResourceId =~ \"{ScopeAuthorityTests.Id}\"", StringComparison.Ordinal)) &&
                text.Contains("| take 11", StringComparison.Ordinal) &&
                !text.Contains("CallerIpAddress", StringComparison.Ordinal);
            return WireBackend.Json(200, Rows(ScopeAuthorityTests.Id));
        });
        _ = new VaultAdministration(administrative, backend);
        var result = await new AuditDiagnostics(monitoring, backend, cloud: cloud).QueryAsync(Query(workspace ? workspaceId : null));
        await Assert.That(result.Status).IsEqualTo(SecretStatus.Success);
        await Assert.That(result.Complete).IsTrue();
        await Assert.That(result.Events.Count).IsEqualTo(1);
        await Assert.That(result.Events[0].Operation).IsEqualTo(AuditOperation.SecretGet);
        await Assert.That(result.RuntimeDeliveryProven).IsFalse();
        await Assert.That(queryScoped).IsTrue();
        await Assert.That(administrative.Audiences.Count).IsEqualTo(0);
        await Assert.That(monitoring.Audiences.Single()).IsEqualTo(directCredential.Audiences.Single());
        await Assert.That(JsonSerializer.Serialize(result).Contains("canary", StringComparison.Ordinal)).IsFalse();
        await Assert.That(JsonSerializer.Serialize(Query(workspaceId)).Contains("44444444", StringComparison.Ordinal)).IsFalse();
    }

    [Test]
    public async Task OverlappingAuditQueriesKeepTheirOwnRoutesAndResults()
    {
        var entered = new TaskCompletionSource(TaskCreationOptions.RunContinuationsAsynchronously);
        var release = new TaskCompletionSource(TaskCreationOptions.RunContinuationsAsynchronously);
        var workspace = Guid.Parse("44444444-4444-4444-4444-444444444444");
        var backend = new WireBackend(async (request, token) =>
        {
            if (request.RequestUri!.AbsolutePath == $"/v1/workspaces/{workspace:D}/query")
            {
                entered.SetResult();
                await release.Task.WaitAsync(token);
                return WireBackend.Json(200, Rows(ScopeAuthorityTests.Id));
            }
            if (request.RequestUri.AbsolutePath == $"/v1{ScopeAuthorityTests.Id}/query")
                return WireBackend.Json(403, """{"error":{"code":"Forbidden","message":"Denied"}}""");
            throw new InvalidOperationException("Unexpected audit route.");
        });
        var client = new AuditDiagnostics(new Credential(), backend);
        var held = client.QueryAsync(Query(workspace)).AsTask();
        try
        {
            await entered.Task.WaitAsync(TimeSpan.FromSeconds(5));
            var denied = await client.QueryAsync(Query());
            await Assert.That(denied.Status).IsEqualTo(SecretStatus.Denied);
            await Assert.That(denied.Events).IsEmpty();
        }
        finally { release.TrySetResult(); }
        var result = await held;
        await Assert.That(result.Status).IsEqualTo(SecretStatus.Success);
        await Assert.That(result.Events.Single().Operation).IsEqualTo(AuditOperation.SecretGet);
    }

    [Test]
    [Arguments("group'quoted")]
    [Arguments("group\\escaped")]
    [Arguments("group\nbroken")]
    public async Task InvalidResourceGroupCannotEnterAuditQuery(string group)
    {
        var subscription = ScopeAuthorityTests.Scope().ResourceGroup.Subscription;
        await Assert.That(() => new ResourceGroupScope(subscription, group)).Throws<ArgumentException>();
    }

    [Test]
    public async Task UndefinedCloudCannotAcquireAuthority()
    {
        var credential = new Credential();
        var backend = new WireBackend((_, _) => throw new InvalidOperationException("Unexpected send."));
        await Assert.That(() => new AuditDiagnostics(credential, backend, cloud: (AuditCloud)99))
            .Throws<ArgumentOutOfRangeException>();
        await Assert.That(credential.Audiences.Count).IsEqualTo(0);
    }

    [Test]
    public async Task PartialErrorsPreserveUsefulRowsWithoutProviderErrorText()
    {
        var backend = new WireBackend((_, _) => Task.FromResult(WireBackend.Json(200,
            Rows(ScopeAuthorityTests.Id, partial: true))));
        var result = await new AuditDiagnostics(new Credential(), backend).QueryAsync(Query());
        await Assert.That(result.Status).IsEqualTo(SecretStatus.Success);
        await Assert.That(result.Events.Count).IsEqualTo(1);
        await Assert.That(result.Complete).IsFalse();
        await Assert.That(result.Error).IsEqualTo(AuditError.PartialFailure);
        await Assert.That(JsonSerializer.Serialize(result).Contains("canary", StringComparison.Ordinal)).IsFalse();
    }

    [Test]
    public async Task ExtraRowsMarkTruncationRatherThanCompleteSuccess()
    {
        var backend = new WireBackend((_, _) => Task.FromResult(WireBackend.Json(200, Rows(ScopeAuthorityTests.Id, 3))));
        var result = await new AuditDiagnostics(new Credential(), backend).QueryAsync(Query(rows: 2));
        await Assert.That(result.Events.Count).IsEqualTo(2);
        await Assert.That(result.Complete).IsFalse();
        await Assert.That(result.Error).IsEqualTo(AuditError.RowLimit);
    }

    [Test]
    [Arguments(false)]
    [Arguments(true)]
    public async Task SubstitutedScopesAndArbitrarySensitiveColumnsAreRejected(bool extraColumn)
    {
        var backend = new WireBackend((_, _) => Task.FromResult(WireBackend.Json(200,
            Rows(extraColumn ? ScopeAuthorityTests.Id : ScopeAuthorityTests.Id.Replace("group-canary", "other-group"),
                extraColumn: extraColumn))));
        var result = await new AuditDiagnostics(new Credential(), backend).QueryAsync(Query());
        await Assert.That(result.Status).IsEqualTo(SecretStatus.Invalid);
        await Assert.That(result.Events.Count).IsEqualTo(0);
        await Assert.That(result.Complete).IsFalse();
    }

    [Test]
    public async Task BatchRetainsStableIndexesAndExplicitErrorsWithoutNativeBatch()
    {
        var failedWorkspace = Guid.Parse("44444444-4444-4444-4444-444444444444");
        var backend = new WireBackend((request, _) =>
        {
            if (request.RequestUri!.AbsolutePath.Contains("$batch", StringComparison.Ordinal))
            {
                throw new InvalidOperationException("Deprecated batch was used.");
            }

            return Task.FromResult(request.RequestUri.AbsolutePath.Contains(failedWorkspace.ToString("D"), StringComparison.Ordinal)
                ? WireBackend.Json(403, """{"error":{"code":"Denied","message":"canary"}}""")
                : WireBackend.Json(200, Rows(ScopeAuthorityTests.Id)));
        });
        var progress = new AuditBatchProgress(3);
        await new AuditDiagnostics(new Credential(), backend).QueryBatchAsync(
            [Query(), Query(failedWorkspace), Query()], progress, TimeSpan.FromSeconds(10));
        await Assert.That(progress.Results[0]!.Status).IsEqualTo(SecretStatus.Success);
        await Assert.That(progress.Results[1]!.Status).IsEqualTo(SecretStatus.Denied);
        await Assert.That(progress.Results[2]!.Status).IsEqualTo(SecretStatus.Success);
    }

    [Test]
    public async Task BatchCancellationRetainsCompletedIndexesAndStopsFurtherRequests()
    {
        var inSecond = new TaskCompletionSource(TaskCreationOptions.RunContinuationsAsynchronously);
        int completed = 0;
        var backend = new WireBackend(async (_, token) =>
        {
            if (completed == 0)
            {
                completed++;
                return WireBackend.Json(200, Rows(ScopeAuthorityTests.Id));
            }

            inSecond.SetResult();
            var barrier = new TaskCompletionSource(TaskCreationOptions.RunContinuationsAsynchronously);
            using var registration = token.Register(() => barrier.TrySetCanceled(token));
            await barrier.Task;
            throw new InvalidOperationException("Cancellation did not stop the transport.");
        });
        var progress = new AuditBatchProgress(3);
        using var cancellation = new CancellationTokenSource();
        var pending = new AuditDiagnostics(new Credential(), backend)
            .QueryBatchAsync([Query(), Query(), Query()], progress, TimeSpan.FromSeconds(30), cancellation.Token).AsTask();
        await inSecond.Task.WaitAsync(TimeSpan.FromSeconds(10));
        cancellation.Cancel();
        bool canceled = false;
        try
        {
            await pending.WaitAsync(TimeSpan.FromSeconds(10));
        }
        catch (OperationCanceledException)
        {
            canceled = true;
        }

        await Assert.That(canceled).IsTrue();
        await Assert.That(progress.Results[0]!.Complete).IsTrue();
        await Assert.That(progress.Results[1]).IsNull();
        await Assert.That(progress.Results[2]).IsNull();
    }

    [Test]
    public async Task WireFailureIsIncompleteWithoutSensitiveException()
    {
        var backend = new WireBackend((_, _) => throw new HttpRequestException("audit-transport-canary"));
        var result = await new AuditDiagnostics(new Credential(), backend).QueryAsync(Query());
        await Assert.That(result.Status).IsEqualTo(SecretStatus.Unavailable);
        await Assert.That(result.Complete).IsFalse();
        await Assert.That(JsonSerializer.Serialize(result).Contains("canary", StringComparison.Ordinal)).IsFalse();
    }

    private sealed class CompletionClock : TimeProvider
    {
        private Timer? _timer;
        private long _ticks;
        public override long TimestampFrequency => TimeSpan.TicksPerSecond;
        public override long GetTimestamp() => _ticks;
        public override DateTimeOffset GetUtcNow() => Start.AddHours(2).AddTicks(_ticks);
        public override ITimer CreateTimer(TimerCallback callback, object? state, TimeSpan dueTime, TimeSpan period)
        {
            _timer = new Timer(callback, state);
            return _timer;
        }
        internal void Expire()
        {
            _ticks += TimeSpan.FromMinutes(1).Ticks;
            _timer?.Fire();
        }
        private sealed class Timer(TimerCallback callback, object? state) : ITimer
        {
            private bool _disposed;
            internal void Fire() { if (!_disposed) callback(state); }
            public bool Change(TimeSpan dueTime, TimeSpan period) => !_disposed;
            public void Dispose() => _disposed = true;
            public ValueTask DisposeAsync() { Dispose(); return ValueTask.CompletedTask; }
        }
    }

    private sealed class EndSignalStream(byte[] bytes, Action end) : Stream
    {
        private readonly MemoryStream _inner = new(bytes, writable: false);
        private bool _ended;
        public override bool CanRead => true;
        public override bool CanSeek => false;
        public override bool CanWrite => false;
        public override long Length => throw new NotSupportedException();
        public override long Position { get => throw new NotSupportedException(); set => throw new NotSupportedException(); }
        public override int Read(byte[] buffer, int offset, int count) => Complete(_inner.Read(buffer, offset, count));
        public override int Read(Span<byte> buffer) => Complete(_inner.Read(buffer));
        public override ValueTask<int> ReadAsync(Memory<byte> buffer, CancellationToken cancellationToken = default)
        {
            cancellationToken.ThrowIfCancellationRequested();
            return ValueTask.FromResult(Complete(_inner.Read(buffer.Span)));
        }
        private int Complete(int count)
        {
            if (count == 0 && !_ended) { _ended = true; end(); }
            return count;
        }
        public override void Flush() { }
        public override long Seek(long offset, SeekOrigin origin) => throw new NotSupportedException();
        public override void SetLength(long value) => throw new NotSupportedException();
        public override void Write(byte[] buffer, int offset, int count) => throw new NotSupportedException();
        protected override void Dispose(bool disposing) { if (disposing) _inner.Dispose(); base.Dispose(disposing); }
    }
}
