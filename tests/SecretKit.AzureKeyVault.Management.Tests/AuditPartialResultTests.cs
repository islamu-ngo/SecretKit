using System.Text.Json;
using SecretKit.Core;

namespace SecretKit.AzureKeyVault.Management.Tests;

public sealed class AuditPartialResultTests
{
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
    [Arguments(false)]
    [Arguments(true)]
    public async Task QueryUsesOnlySelectedMonitoringIdentityAndCanonicalSinglePost(bool workspace)
    {
        var administrative = new Credential();
        var monitoring = new Credential();
        var workspaceId = Guid.Parse("44444444-4444-4444-4444-444444444444");
        bool queryScoped = false;
        var backend = new WireBackend(async (request, token) =>
        {
            if (request.RequestUri!.Host != "api.loganalytics.io" || request.Method != HttpMethod.Post ||
                request.RequestUri.AbsolutePath != (workspace ? $"/v1/workspaces/{workspaceId:D}/query" :
                    $"/v1{ScopeAuthorityTests.Id}/query"))
            {
                throw new InvalidOperationException("Wrong monitoring route.");
            }

            using var body = JsonDocument.Parse(await request.Content!.ReadAsStringAsync(token));
            var text = body.RootElement.GetProperty("query").GetString()!;
            queryScoped = text.Contains(ScopeAuthorityTests.Id, StringComparison.Ordinal) &&
                text.Contains("| take 11", StringComparison.Ordinal) &&
                !text.Contains("CallerIpAddress", StringComparison.Ordinal);
            return WireBackend.Json(200, Rows(ScopeAuthorityTests.Id));
        });
        _ = new VaultAdministration(administrative, backend);
        var result = await new AuditDiagnostics(monitoring, backend).QueryAsync(Query(workspace ? workspaceId : null));
        await Assert.That(result.Status).IsEqualTo(SecretStatus.Success);
        await Assert.That(result.Complete).IsTrue();
        await Assert.That(result.Events.Count).IsEqualTo(1);
        await Assert.That(result.Events[0].Operation).IsEqualTo(AuditOperation.SecretGet);
        await Assert.That(result.RuntimeDeliveryProven).IsFalse();
        await Assert.That(queryScoped).IsTrue();
        await Assert.That(administrative.Audiences.Count).IsEqualTo(0);
        await Assert.That(string.Join(",", monitoring.Audiences)).IsEqualTo("https://api.loganalytics.io//.default");
        await Assert.That(JsonSerializer.Serialize(result).Contains("canary", StringComparison.Ordinal)).IsFalse();
        await Assert.That(JsonSerializer.Serialize(Query(workspaceId)).Contains("44444444", StringComparison.Ordinal)).IsFalse();
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
}
