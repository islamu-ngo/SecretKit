using System.Security.Cryptography;
using System.Text.Json;
using SecretKit.Core;

namespace SecretKit.Infisical.Tests;

public sealed class ImportEffectTests
{
    [Test]
    [Arguments(false)]
    [Arguments(true)]
    public async Task ImportConfigurationReplicationAndDestinationPolicyAreIndependent(bool approvalPolicy)
    {
        var state = new ImportState { DestinationPolicy = approvalPolicy };
        await using InfisicalClient observer = Phase5TestSupport.Client(new ImportBackend(state), "observer");
        await using InfisicalClient intended = Phase5TestSupport.Client(new ImportBackend(state), "intended");
        var target = ImportTarget(observer);
        var receipt = new MutationReceipt(target);
        InfisicalImport import = (await observer.CreateImportAsync(target, new("source", "/shared"), true,
            Phase5TestSupport.Admin(observer), receipt)).Value;
        await Assert.That(receipt.Evidence).IsEqualTo(DispatchEvidence.Applied);
        await Assert.That(import.IsReplication).IsTrue();
        await Assert.That(state.Import is not null).IsTrue();
        var observedTarget = ImportTarget(observer, import.Id);
        var readTarget = SecretTarget(intended);
        InfisicalImportEffectObservation observation = (await observer.ObserveImportEffectsAsync(observedTarget, intended, readTarget)).Value;
        await Assert.That(observation.ImportCreated).IsEqualTo(InfisicalEffectEvidence.Observed);
        await Assert.That(observation.ReplicationRequested).IsTrue();
        await Assert.That(observation.Destination).IsEqualTo(InfisicalDestinationEvidence.Unknown);
        await Assert.That(observation.DeliveryStatus).IsEqualTo(approvalPolicy ? SecretStatus.Absent : SecretStatus.Success);
        await Assert.That(observation.FreshIntendedReadSucceeded).IsEqualTo(!approvalPolicy);
        // Even the server's success report cannot establish approval policy merge/completeness.
        await Assert.That(observation.ReplicationReportedSuccessful).IsTrue();
        if (approvalPolicy)
        {
            state.ApplyDestinationApproval();
            InfisicalImportEffectObservation afterApproval = (await observer.ObserveImportEffectsAsync(observedTarget, intended, readTarget)).Value;
            await Assert.That(afterApproval.DeliveryStatus).IsEqualTo(SecretStatus.Success);
            await Assert.That(afterApproval.Destination).IsEqualTo(InfisicalDestinationEvidence.Unknown);
        }
        await Assert.That(JsonSerializer.Serialize(observation).Contains(state.SourceValue, StringComparison.Ordinal)).IsFalse();
        await Assert.That(JsonSerializer.Serialize(import).Contains("/shared", StringComparison.Ordinal)).IsFalse();
    }

    [Test]
    public async Task FreshIntendedDenialNeverUsesSuccessfulAdminRead()
    {
        var state = new ImportState { DenyIntended = true };
        await using InfisicalClient admin = Phase5TestSupport.Client(new ImportBackend(state), "admin");
        await using InfisicalClient intended = Phase5TestSupport.Client(new ImportBackend(state), "intended");
        var target = ImportTarget(admin);
        InfisicalImport import = (await admin.CreateImportAsync(target, new("source", "/shared"), true,
            Phase5TestSupport.Admin(admin), new(target))).Value;
        using SecretRead adminRead = (await admin.ReadAsync(SecretTarget(admin))).Value;
        await Assert.That(adminRead.Material.Reveal()).IsEqualTo(state.SourceValue);
        var observedTarget = ImportTarget(admin, import.Id);
        InfisicalImportEffectObservation result = (await admin.ObserveImportEffectsAsync(observedTarget, intended, SecretTarget(intended))).Value;
        await Assert.That(result.VisibilityStatus).IsEqualTo(SecretStatus.Success);
        await Assert.That(result.DeliveryStatus).IsEqualTo(SecretStatus.Denied);
        await Assert.That(result.FreshIntendedReadSucceeded).IsFalse();
        state.DenyIntended = false;
        await Assert.That((await admin.ObserveImportEffectsAsync(observedTarget, intended, SecretTarget(intended))).Value.FreshIntendedReadSucceeded).IsTrue();
    }

    [Test]
    public async Task ImportListUpdateDeleteAndGroupedValuesUseCurrentWireContracts()
    {
        var state = new ImportState();
        await using InfisicalClient client = Phase5TestSupport.Client(new ImportBackend(state));
        InfisicalNativeAuthority admin = Phase5TestSupport.Admin(client);
        var create = ImportTarget(client);
        InfisicalImport import = (await client.CreateImportAsync(create, new("source", "/shared", "source-project"), false, admin, new(create))).Value;
        await Assert.That((await client.ListImportsAsync(create)).Value.Items.Single().Id).IsEqualTo(import.Id);
        var byId = ImportTarget(client, import.Id);
        await Assert.That((await client.GetImportAsync(byId)).Value.FolderId).IsEqualTo(Phase5TestSupport.Id);
        await Assert.That((await client.UpdateImportAsync(byId, admin, new(byId), position: 2)).Value.Position).IsEqualTo(2d);
        using InfisicalImportedSecrets grouped = (await client.ReadImportedSecretsAsync(create)).Value;
        await Assert.That(grouped.Items.Single().Material.Reveal()).IsEqualTo(state.SourceValue);
        await Assert.That(grouped.Items.Single().Environment).IsEqualTo("source");
        await Assert.That(grouped.IsComplete).IsTrue();
        await Assert.That(JsonSerializer.Serialize(grouped).Contains(state.SourceValue, StringComparison.Ordinal)).IsFalse();
        await Assert.That((await client.DeleteImportAsync(byId, admin, new(byId))).Value.Id).IsEqualTo(import.Id);
        await Assert.That((await client.ListImportsAsync(create)).Value.Items.Count).IsEqualTo(0);
        await Assert.That((await client.GetImportAsync(byId)).Status).IsEqualTo(SecretStatus.Absent);
    }

    [Test]
    [Arguments(false)]
    [Arguments(true)]
    public async Task ImportLostResponseAndCancellationRetainConfigurationUncertainty(bool cancel)
    {
        var state = new ImportState { DropResponse = !cancel, HoldResponse = cancel };
        await using InfisicalClient client = Phase5TestSupport.Client(new ImportBackend(state));
        var target = ImportTarget(client);
        var receipt = new MutationReceipt(target);
        using var cancellation = new CancellationTokenSource();
        Task<SecretOutcome<InfisicalImport>> pending = client.CreateImportAsync(target, new("source", "/shared"), false,
            Phase5TestSupport.Admin(client), receipt, cancellation.Token).AsTask();
        if (cancel)
        {
            await state.Committed.Task.WaitAsync(TimeSpan.FromSeconds(5));
            cancellation.Cancel();
            await Assert.That(async () => await pending).Throws<OperationCanceledException>();
        }
        else
        {
            await Assert.That((await pending).Status).IsEqualTo(SecretStatus.Unknown);
        }
        await Assert.That(receipt.Evidence).IsEqualTo(DispatchEvidence.PossiblyDispatched);
        await Assert.That((await client.ListImportsAsync(target)).Value.Items.Count).IsEqualTo(1);
        await Assert.That((await client.CreateImportAsync(target, new("source", "/shared"), false,
            Phase5TestSupport.Admin(client), receipt)).Status).IsEqualTo(SecretStatus.Invalid);
        await Assert.That((await client.ListImportsAsync(target)).Value.Items.Count).IsEqualTo(1);
    }

    [Test]
    public async Task PreCanceledAndWrongDestinationAuthorityCannotProvision()
    {
        var state = new ImportState();
        await using InfisicalClient client = Phase5TestSupport.Client(new ImportBackend(state));
        var target = ImportTarget(client);
        var receipt = new MutationReceipt(target);
        using var cancellation = new CancellationTokenSource();
        cancellation.Cancel();
        var admin = new InfisicalNativeAuthority(client.Authority, new Phase5TestSupport.Tokens("admin", true), "project");
        await Assert.That(async () => await client.CreateImportAsync(target, new("source", "/shared"), true,
            admin, receipt, cancellation.Token)).Throws<OperationCanceledException>();
        await Assert.That(receipt.Evidence).IsEqualTo(DispatchEvidence.NotDispatched);
        var wrongScope = new InfisicalNativeAuthority(client.Authority, new Phase5TestSupport.Tokens("admin", true), "project", "dev", "/elsewhere");
        await Assert.That((await client.CreateImportAsync(target, new("source", "/shared"), true, wrongScope, receipt)).Status).IsEqualTo(SecretStatus.Invalid);
        await Assert.That(state.Import is null).IsTrue();
    }

    [Test]
    [Arguments(false)]
    [Arguments(true)]
    public async Task BulkAppliedAndApprovalPendingAreNotEquivalent(bool pendingApproval)
    {
        var state = new ImportState { DestinationPolicy = pendingApproval };
        await using InfisicalClient client = Phase5TestSupport.Client(new ImportBackend(state));
        var target = BulkTarget(client);
        var receipt = new MutationReceipt(target);
        using SecretMaterial material = SecretMaterial.FromText(state.SourceValue);
        var input = new InfisicalBulkSecret("key", material, metadata: [new("label", "protected-metadata")],
            creationMetadata: new Dictionary<string, string> { ["migration"] = "reviewed" });
        InfisicalBulkObservation result = (await client.CreateSecretsAsync(target, [input],
            Phase5TestSupport.Admin(client), receipt)).Value;
        await Assert.That(result.AllApplied).IsEqualTo(!pendingApproval);
        await Assert.That(result.ApprovalPending).IsEqualTo(pendingApproval);
        await Assert.That(receipt.Evidence).IsEqualTo(pendingApproval ? DispatchEvidence.Pending : DispatchEvidence.Applied);
        await Assert.That((await client.ReadAsync(SecretTarget(client))).Status).IsEqualTo(pendingApproval ? SecretStatus.Absent : SecretStatus.Success);
        await Assert.That(material.Reveal()).IsEqualTo(state.SourceValue);
        await Assert.That(JsonSerializer.Serialize(input).Contains(state.SourceValue, StringComparison.Ordinal)).IsFalse();
    }

    [Test]
    public async Task BulkPartialEffectsRetainUnknownRowsWithoutReplay()
    {
        var state = new ImportState { PartialBulk = true };
        await using InfisicalClient client = Phase5TestSupport.Client(new ImportBackend(state));
        var target = BulkTarget(client);
        var receipt = new MutationReceipt(target);
        using SecretMaterial one = SecretMaterial.FromText(state.SourceValue);
        using SecretMaterial two = SecretMaterial.FromText("second-value");
        InfisicalBulkObservation result = (await client.CreateSecretsAsync(target, [new("key", one), new("other", two)],
            Phase5TestSupport.Admin(client), receipt)).Value;
        await Assert.That(result.AllApplied).IsFalse();
        await Assert.That(result.Items[0].Evidence).IsEqualTo(DispatchEvidence.Applied);
        await Assert.That(result.Items[1].Evidence).IsEqualTo(DispatchEvidence.PossiblyDispatched);
        await Assert.That(receipt.Evidence).IsEqualTo(DispatchEvidence.PossiblyDispatched);
        using SecretRead read = (await client.ReadAsync(SecretTarget(client))).Value;
        await Assert.That(read.Material.Reveal()).IsEqualTo(state.SourceValue);
        await Assert.That(state.Values.ContainsKey("other")).IsFalse();
        await Assert.That((await client.CreateSecretsAsync(target, [new("key", one)], Phase5TestSupport.Admin(client), receipt)).Status).IsEqualTo(SecretStatus.Invalid);
        await Assert.That(state.Versions["key"]).IsEqualTo(1);
    }

    [Test]
    public async Task BulkUpdateAndDeleteKeepNativeModesAndSelectedTypes()
    {
        var state = new ImportState();
        await using InfisicalClient client = Phase5TestSupport.Client(new ImportBackend(state));
        var target = BulkTarget(client);
        InfisicalNativeAuthority admin = Phase5TestSupport.Admin(client);
        using SecretMaterial value = SecretMaterial.FromText(state.SourceValue);
        _ = (await client.CreateSecretsAsync(target, [new("key", value)], admin, new(target))).Value;
        using SecretMaterial replacement = SecretMaterial.FromText("changed-value");
        var update = new InfisicalBulkSecret("key", replacement, newName: "renamed", clearReminderNote: true,
            clearReminderRepeatDays: true, skipMultilineEncoding: true);
        await Assert.That((await client.UpdateSecretsAsync(target, [update], admin, new(target), InfisicalBulkUpdateMode.Upsert)).Value.AllApplied).IsTrue();
        await Assert.That(state.Values["renamed"]).IsEqualTo("changed-value");
        await Assert.That(state.LastMode).IsEqualTo("upsert");
        await Assert.That((await client.DeleteSecretsAsync(target, [new("renamed")], admin, new(target))).Value.AllApplied).IsTrue();
        await Assert.That(state.Values.ContainsKey("renamed")).IsFalse();
    }

    [Test]
    [Arguments(false)]
    [Arguments(true)]
    public async Task BulkConflictAndLostResponseKeepDistinctEvidence(bool lostResponse)
    {
        var state = new ImportState { Conflict = !lostResponse, DropResponse = lostResponse };
        await using InfisicalClient client = Phase5TestSupport.Client(new ImportBackend(state));
        var target = BulkTarget(client);
        var receipt = new MutationReceipt(target);
        using SecretMaterial value = SecretMaterial.FromText(state.SourceValue);
        SecretOutcome<InfisicalBulkObservation> result = await client.CreateSecretsAsync(target, [new("key", value)], Phase5TestSupport.Admin(client), receipt);
        await Assert.That(result.Status).IsEqualTo(lostResponse ? SecretStatus.Unknown : SecretStatus.Conflict);
        await Assert.That(receipt.Evidence).IsEqualTo(lostResponse ? DispatchEvidence.PossiblyDispatched : DispatchEvidence.Conflict);
        await Assert.That(state.Values.ContainsKey("key")).IsEqualTo(lostResponse);
    }

    [Test]
    public async Task BulkBoundsAndAmbiguousApprovalResponseFailClosed()
    {
        var state = new ImportState { AmbiguousApproval = true };
        await using InfisicalClient client = Phase5TestSupport.Client(new ImportBackend(state), responseLimit: 1024);
        var target = BulkTarget(client);
        var receipt = new MutationReceipt(target);
        var forbidden = new InfisicalNativeAuthority(client.Authority, new Phase5TestSupport.Tokens("admin", true), "project");
        using SecretMaterial large = SecretMaterial.FromText(new string('v', 2048));
        await Assert.That((await client.CreateSecretsAsync(target, [new("key", large)], forbidden, receipt)).Status).IsEqualTo(SecretStatus.Invalid);
        await Assert.That((await client.CreateSecretsAsync(target, Enumerable.Range(0, 129).Select(index => new InfisicalBulkSecret("key" + index, large)).ToArray(),
            forbidden, receipt)).Status).IsEqualTo(SecretStatus.Invalid);
        await Assert.That(receipt.Evidence).IsEqualTo(DispatchEvidence.NotDispatched);
        using SecretMaterial value = SecretMaterial.FromText("value");
        await Assert.That((await client.CreateSecretsAsync(target, [new("key", value)], Phase5TestSupport.Admin(client), receipt)).Status).IsEqualTo(SecretStatus.Unknown);
        await Assert.That(receipt.Evidence).IsEqualTo(DispatchEvidence.PossiblyDispatched);
    }

    [Test]
    [Arguments(false)]
    [Arguments(true)]
    public async Task ApprovalRequiresObservedMatchingDestinationFolder(bool missingFolderIdentity)
    {
        var state = new ImportState { DestinationPolicy = true, WrongApprovalFolder = !missingFolderIdentity };
        await using InfisicalClient client = Phase5TestSupport.Client(new ImportBackend(state));
        var target = new SecretReference(client.Authority,
            new InfisicalBulkAddress("project", "dev", "/", missingFolderIdentity ? null : Phase5TestSupport.Id));
        var receipt = new MutationReceipt(target);
        using SecretMaterial value = SecretMaterial.FromText("value");
        await Assert.That((await client.CreateSecretsAsync(target, [new("key", value)],
            Phase5TestSupport.Admin(client), receipt)).Status).IsEqualTo(SecretStatus.Unknown);
        await Assert.That(receipt.Evidence).IsEqualTo(DispatchEvidence.PossiblyDispatched);
        await Assert.That(state.Values.ContainsKey("key")).IsFalse();
    }

    [Test]
    public async Task FreshReaderCannotObserveDifferentDestinationOrHistoricalReference()
    {
        var state = new ImportState();
        var forbidden = new Phase5TestSupport.Tokens("admin", true);
        await using var observer = new InfisicalClient(new Uri("https://infisical.test"), forbidden,
            new InfisicalNetworkOptions(), null, new ImportBackend(state));
        await using var intended = new InfisicalClient(new Uri("https://infisical.test"), forbidden,
            new InfisicalNetworkOptions(), null, new ImportBackend(state));
        var target = ImportTarget(observer, Phase5TestSupport.OtherId);
        var wrongDestination = new SecretReference(intended.Authority, new InfisicalSecretAddress("project", "prod", "/", "key"));
        await Assert.That((await observer.ObserveImportEffectsAsync(target, intended, wrongDestination)).Status).IsEqualTo(SecretStatus.Invalid);
        var historical = new SecretReference(intended.Authority, new InfisicalSecretAddress("project", "dev", "/", "key", 1));
        await Assert.That((await observer.ObserveImportEffectsAsync(target, intended, historical)).Status).IsEqualTo(SecretStatus.Invalid);
    }

    private static SecretReference ImportTarget(InfisicalClient client, string? id = null) =>
        new(client.Authority, new InfisicalImportAddress("project", "dev", "/", Phase5TestSupport.Id, id));
    private static SecretReference BulkTarget(InfisicalClient client) =>
        new(client.Authority, new InfisicalBulkAddress("project", "dev", "/", Phase5TestSupport.Id));
    private static SecretReference SecretTarget(InfisicalClient client) =>
        new(client.Authority, new InfisicalSecretAddress("project", "dev", "/", "key"));

    private sealed class ImportState
    {
        public string SourceValue { get; } = Convert.ToBase64String(RandomNumberGenerator.GetBytes(32));
        public Dictionary<string, object?>? Import { get; set; }
        public Dictionary<string, string> Values { get; } = new(StringComparer.Ordinal);
        public Dictionary<string, int> Versions { get; } = new(StringComparer.Ordinal);
        public bool DestinationPolicy { get; init; }
        public bool DenyIntended { get; set; }
        public bool DropResponse { get; init; }
        public bool HoldResponse { get; init; }
        public bool PartialBulk { get; init; }
        public bool Conflict { get; init; }
        public bool AmbiguousApproval { get; init; }
        public bool WrongApprovalFolder { get; init; }
        public string? LastMode { get; set; }
        public TaskCompletionSource Committed { get; } = new(TaskCreationOptions.RunContinuationsAsynchronously);
        public TaskCompletionSource ResponseRelease { get; } = new(TaskCreationOptions.RunContinuationsAsynchronously);
        public void ApplyDestinationApproval() { Values["key"] = SourceValue; Versions["key"] = 1; }
    }

    private sealed class ImportBackend(ImportState state) : HttpMessageHandler
    {
        protected override async Task<HttpResponseMessage> SendAsync(HttpRequestMessage request, CancellationToken cancellationToken)
        {
            string path = request.RequestUri!.AbsolutePath;
            if (request.Method != HttpMethod.Get && request.Headers.Authorization?.Parameter != "admin")
            {
                return Phase5TestSupport.Json(403, new { });
            }
            if (request.Method != HttpMethod.Get && state.Conflict) { return Phase5TestSupport.Json(409, new { }); }
            if (request.Method == HttpMethod.Get && path.StartsWith("/api/v4/secrets/", StringComparison.Ordinal))
            {
                if (request.Headers.Authorization?.Parameter == "intended" && state.DenyIntended)
                {
                    return Phase5TestSupport.Json(403, new { error = state.SourceValue });
                }
                string key = Uri.UnescapeDataString(path["/api/v4/secrets/".Length..]);
                return state.Values.TryGetValue(key, out string? value) ? Phase5TestSupport.Json(200, new
                {
                    secret = new { secretKey = key, secretValue = value, secretValueHidden = false, version = state.Versions[key] }
                }) : Phase5TestSupport.Json(404, new { });
            }
            if (request.Method == HttpMethod.Get && path == "/api/v2/secret-imports/secrets")
            {
                return Phase5TestSupport.Json(200, new
                {
                    secrets = new[] { new {
                    environment = "source", secretPath = "/shared", folderId = Phase5TestSupport.OtherId,
                    environmentInfo = new { id = Phase5TestSupport.EnvironmentId, name = "source", slug = "source" },
                    secrets = new[] { new {
                        secretKey = "key", secretValue = state.SourceValue, workspace = "source-project",
                        environment = "source", version = 1, type = "shared"
                    } }
                } }
                });
            }
            if (request.Method == HttpMethod.Get && path == "/api/v2/secret-imports")
            {
                if (!request.RequestUri.Query.Contains("path=%2F", StringComparison.Ordinal)) { return Phase5TestSupport.Json(400, new { }); }
                return Phase5TestSupport.Json(200, new { secretImports = state.Import is null ? [] : new[] { state.Import } });
            }
            if (request.Method == HttpMethod.Get && path.StartsWith("/api/v2/secret-imports/", StringComparison.Ordinal))
            {
                if (state.Import is null) { return Phase5TestSupport.Json(404, new { }); }
                return Phase5TestSupport.Json(200, new
                {
                    secretImport = new Dictionary<string, object?>(state.Import)
                    {
                        ["projectId"] = "project",
                        ["secretPath"] = "/",
                        ["environment"] = new { id = Phase5TestSupport.EnvironmentId, name = "dev", slug = "dev" }
                    }
                });
            }
            using JsonDocument body = JsonDocument.Parse(await request.Content!.ReadAsByteArrayAsync(cancellationToken));
            if (body.RootElement.GetProperty("projectId").GetString() != "project" ||
                body.RootElement.GetProperty("environment").GetString() != "dev")
            {
                return Phase5TestSupport.Json(400, new { });
            }
            object response;
            if (path.StartsWith("/api/v2/secret-imports", StringComparison.Ordinal))
            {
                if (body.RootElement.GetProperty("path").GetString() != "/") { return Phase5TestSupport.Json(400, new { }); }
                if (request.Method == HttpMethod.Post)
                {
                    JsonElement import = body.RootElement.GetProperty("import");
                    bool replication = body.RootElement.GetProperty("isReplication").GetBoolean();
                    state.Import = new Dictionary<string, object?>
                    {
                        ["id"] = Phase5TestSupport.OtherId,
                        ["folderId"] = Phase5TestSupport.Id,
                        ["importEnv"] = new { id = Phase5TestSupport.EnvironmentId, name = "source", slug = import.GetProperty("environment").GetString() },
                        ["importPath"] = import.GetProperty("path").GetString(),
                        ["position"] = 1,
                        ["createdAt"] = Phase5TestSupport.Date,
                        ["updatedAt"] = Phase5TestSupport.Date,
                        ["isReplication"] = replication,
                        ["isReplicationSuccess"] = true,
                        ["replicationStatus"] = state.DestinationPolicy ? "unestablished-approval-text" : "unestablished-success-text"
                    };
                    if (replication && !state.DestinationPolicy) { state.ApplyDestinationApproval(); }
                }
                if (state.Import is null) { return Phase5TestSupport.Json(404, new { }); }
                if (request.Method == HttpMethod.Patch)
                {
                    JsonElement import = body.RootElement.GetProperty("import");
                    if (import.TryGetProperty("position", out JsonElement position)) { state.Import["position"] = position.GetDouble(); }
                }
                response = new { secretImport = state.Import };
                if (request.Method == HttpMethod.Delete) { state.Import = null; }
            }
            else if (path == "/api/v4/secrets/batch")
            {
                if (body.RootElement.GetProperty("secretPath").GetString() != "/") { return Phase5TestSupport.Json(400, new { }); }
                if (state.DestinationPolicy || state.AmbiguousApproval)
                {
                    return Phase5TestSupport.Json(200, state.AmbiguousApproval ?
                        new { approval = new { id = Phase5TestSupport.Id, folderId = Phase5TestSupport.Id, policyId = Phase5TestSupport.OtherId, hasMerged = false }, secrets = Array.Empty<object>() } :
                        (object)new
                        {
                            approval = new
                            {
                                id = Phase5TestSupport.Id,
                                folderId = state.WrongApprovalFolder ? Phase5TestSupport.OtherId : Phase5TestSupport.Id,
                                policyId = Phase5TestSupport.OtherId,
                                hasMerged = false
                            }
                        });
                }
                state.LastMode = body.RootElement.TryGetProperty("mode", out JsonElement mode) ? mode.GetString() : null;
                var results = new List<object>();
                foreach (JsonElement input in body.RootElement.GetProperty("secrets").EnumerateArray())
                {
                    string key = input.GetProperty("secretKey").GetString()!;
                    int version = state.Versions.TryGetValue(key, out int current) ? current + 1 : 1;
                    if (request.Method == HttpMethod.Delete)
                    {
                        state.Values.Remove(key);
                    }
                    else
                    {
                        string value = input.TryGetProperty("secretValue", out JsonElement material) ? material.GetString()! : state.Values[key];
                        if (input.TryGetProperty("newSecretName", out JsonElement newName))
                        {
                            state.Values.Remove(key);
                            key = newName.GetString()!;
                        }
                        state.Values[key] = value;
                        state.Versions[key] = version;
                    }
                    results.Add(new
                    {
                        secretKey = key,
                        workspace = "project",
                        environment = "dev",
                        version,
                        type = input.TryGetProperty("type", out JsonElement type) ? type.GetString() : "shared",
                        secretValue = state.SourceValue
                    });
                    if (state.PartialBulk) { break; }
                }
                response = new { secrets = results };
            }
            else { throw new InvalidOperationException("Unexpected import route."); }
            state.Committed.TrySetResult();
            if (state.DropResponse) { throw new HttpRequestException("Untrusted wire error containing " + state.SourceValue); }
            if (state.HoldResponse) { await state.ResponseRelease.Task.WaitAsync(cancellationToken); }
            return Phase5TestSupport.Json(200, response);
        }
    }
}
