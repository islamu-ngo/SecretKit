using System.Net;
using System.Text.Json;
using Azure.Core.Pipeline;
using SecretKit.AzureKeyVault.Conformance.Tests.Admission.Management;
using SecretKit.AzureKeyVault.Management;
using SecretKit.TestFixtures;

namespace SecretKit.AzureKeyVault.Conformance.Tests;

public sealed class AzureAuditEffectValidationTests
{
    private const string Trigger = "selected-trigger";
    private static readonly DateTimeOffset Start = new(2026, 1, 1, 0, 0, 0, TimeSpan.Zero);

    [Test]
    [Arguments("complete", false)]
    [Arguments("complete", true)]
    [Arguments("partial-failure", false)]
    [Arguments("partial-failure", true)]
    [Arguments("row-limit", false)]
    [Arguments("row-limit", true)]
    public async Task DuplicateSubstitutionCannotReplaceIndependentOccurrences(string mode, bool workspace)
    {
        AuditQuery query = Query(mode, workspace);
        AuditQueryResult result = await ParseAsync(query, mode, [AuditOperation.SecretGet, AuditOperation.SecretGet]);
        AuditDiagnosticsEffects.MeasuredEvent[] observed =
        [
            Measured(query, AuditOperation.SecretGet, Trigger),
            Measured(query, AuditOperation.SecretList, "independent-list")
        ];
        if (mode != "complete")
            observed = [.. observed, Measured(query, AuditOperation.SecretSet, "independent-set")];

        await Assert.That(() => AuditDiagnosticsEffects.MatchEvents(result, query, observed, Trigger))
            .Throws<NativeCaseFailureException>();
    }

    [Test]
    [Arguments("complete", false)]
    [Arguments("complete", true)]
    [Arguments("partial-failure", false)]
    [Arguments("partial-failure", true)]
    [Arguments("row-limit", false)]
    [Arguments("row-limit", true)]
    public async Task IdenticalPublicProjectionsRetainBothIndependentOccurrences(string mode, bool workspace)
    {
        AuditQuery query = Query(mode, workspace);
        AuditQueryResult result = await ParseAsync(query, mode, [AuditOperation.SecretGet, AuditOperation.SecretGet]);
        AuditDiagnosticsEffects.MeasuredEvent[] observed =
        [
            Measured(query, AuditOperation.SecretGet, "independent-get"),
            Measured(query, AuditOperation.SecretGet, Trigger)
        ];
        if (mode != "complete")
            observed = [.. observed, Measured(query, AuditOperation.SecretSet, "independent-set")];

        await Assert.That(result.Events.Count).IsEqualTo(2);
        AuditDiagnosticsEffects.MatchEvents(result, query, observed, Trigger);
    }

    [Test]
    [Arguments("partial-failure", false)]
    [Arguments("partial-failure", true)]
    [Arguments("row-limit", false)]
    [Arguments("row-limit", true)]
    public async Task BoundedSubsetConsumesOnlyReturnedIndependentOccurrences(string mode, bool workspace)
    {
        AuditQuery query = Query(mode, workspace);
        AuditQueryResult result = await ParseAsync(query, mode, [AuditOperation.SecretGet, AuditOperation.SecretList]);
        AuditDiagnosticsEffects.MatchEvents(result, query,
        [
            Measured(query, AuditOperation.SecretGet, Trigger),
            Measured(query, AuditOperation.SecretList, "independent-list"),
            Measured(query, AuditOperation.SecretSet, "independent-set")
        ], Trigger);
    }

    [Test]
    [Arguments("partial-failure")]
    [Arguments("row-limit")]
    public async Task BoundedSubsetStillRequiresSelectedTriggerWitness(string mode)
    {
        AuditQuery query = Query(mode, false);
        AuditQueryResult result = await ParseAsync(query, mode, [AuditOperation.SecretList, AuditOperation.SecretSet]);
        await Assert.That(() => AuditDiagnosticsEffects.MatchEvents(result, query,
        [
            Measured(query, AuditOperation.SecretGet, Trigger),
            Measured(query, AuditOperation.SecretList, "independent-list"),
            Measured(query, AuditOperation.SecretSet, "independent-set")
        ], Trigger)).Throws<NativeCaseFailureException>();
    }

    [Test]
    public async Task CompleteResultCannotOmitIndependentOccurrence()
    {
        AuditQuery query = Query("complete", false);
        AuditQueryResult result = await ParseAsync(query, "complete", [AuditOperation.SecretGet]);
        await Assert.That(() => AuditDiagnosticsEffects.MatchEvents(result, query,
        [
            Measured(query, AuditOperation.SecretGet, Trigger),
            Measured(query, AuditOperation.SecretGet, "independent-get")
        ], Trigger)).Throws<NativeCaseFailureException>();
    }

    private static AuditQuery Query(string mode, bool workspace) =>
        new(new(new(new(Guid.Parse("11111111-1111-1111-1111-111111111111")), "owned-group"), "owned-vault"),
            Start, Start.AddHours(1), mode == "row-limit" ? 2 : 10,
            workspaceId: workspace ? Guid.Parse("22222222-2222-2222-2222-222222222222") : null);

    private static AuditDiagnosticsEffects.MeasuredEvent Measured(AuditQuery query, AuditOperation operation, string trigger) =>
        new(query.Vault.ExportResourceId(), query.WorkspaceId, Start, operation, AuditResultKind.Success, trigger);

    private static async Task<AuditQueryResult> ParseAsync(AuditQuery query, string mode, AuditOperation[] operations)
    {
        if (mode == "row-limit")
            operations = [.. operations, AuditOperation.SecretSet];
        string rows = JsonSerializer.Serialize(operations.Select(operation => new object[]
        {
            Start.ToString("O"), operation.ToString(), "Success", query.Vault.ExportResourceId(), "AuditEvent"
        }));
        string error = mode == "partial-failure"
            ? ""","error":{"code":"PartialError","message":"withheld","details":[{"code":"LimitsExceeded","message":"withheld"}]}"""
            : "";
        string body = $$$"""{"tables":[{"name":"PrimaryResult","columns":[{"name":"TimeGenerated","type":"datetime"},{"name":"OperationName","type":"string"},{"name":"ResultType","type":"string"},{"name":"_ResourceId","type":"string"},{"name":"Category","type":"string"}],"rows":{{{rows}}}}]{{{error}}}}""";
        using var backend = new Backend(body);
        using var http = new HttpClient(backend);
        using var credential = new SelectedAudienceCredential(new("offline-monitoring", DateTimeOffset.MaxValue,
            "https://api.loganalytics.io//.default"));
        AuditQueryResult result = await new AuditDiagnostics(credential, new HttpClientTransport(http)).QueryAsync(query);
        AuditDiagnosticsEffects.ValidateResult(result, "result." + mode);
        return result;
    }

    private sealed class Backend(string body) : HttpMessageHandler
    {
        protected override Task<HttpResponseMessage> SendAsync(HttpRequestMessage request, CancellationToken cancellationToken) =>
            Task.FromResult(new HttpResponseMessage(HttpStatusCode.OK)
            {
                Content = new StringContent(body, System.Text.Encoding.UTF8, "application/json")
            });
    }
}
