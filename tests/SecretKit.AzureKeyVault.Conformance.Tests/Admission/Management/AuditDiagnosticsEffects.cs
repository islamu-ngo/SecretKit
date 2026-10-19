using Azure.Core.Pipeline;
using SecretKit.AzureKeyVault;
using SecretKit.AzureKeyVault.Management;
using SecretKit.Core;
using SecretKit.TestFixtures;

namespace SecretKit.AzureKeyVault.Conformance.Tests.Admission.Management;

internal static class AuditDiagnosticsEffects
{
    private const string Prefix = "a.management.AuditDiagnostics.";
    private const string Type = "SecretKit.AzureKeyVault.Management.";
    internal static readonly string[] QueryVariants =
    [
        "query.resource", "query.workspace", "result.complete", "result.partial-failure", "result.row-limit",
        "result.deadline", "operation.Unknown", "operation.SecretGet", "operation.SecretList", "operation.SecretSet",
        "operation.SecretDelete", "operation.SecretRecover", "operation.SecretBackup", "operation.SecretRestore", "operation.SecretPurge"
    ];
    internal static readonly ManagementMember[] Members =
    [
        new(Prefix + "QueryAsync", Type + "AuditDiagnostics.QueryAsync(" + Type + "AuditQuery,System.Threading.CancellationToken)", QueryVariants, false),
        new(Prefix + "QueryBatchAsync", Type + "AuditDiagnostics.QueryBatchAsync(System.Collections.Generic.IReadOnlyList<" + Type +
            "AuditQuery>," + Type + "AuditBatchProgress,System.TimeSpan,System.Threading.CancellationToken)",
            [.. QueryVariants, "batch.single", "batch.multiple", "batch.mixed-resource-workspace", "batch.caller-cancellation-progress"], false)
    ];

    public static void Register(NativeCaseRegistry registry, OwnedAzureEnvironment env,
        IReadOnlyList<NativeCaseDefinition> expected, Func<ObserverEndpoint, OwnedManagementObserver>? createObserver = null,
        HttpPipelineTransport? runtimeTransport = null, HttpPipelineTransport? monitoringTransport = null,
        SelectedInvocation? selectedInvocation = null) =>
        ManagementAdmission.Register(registry, env, expected, Members,
            (d, p, t) => ExecuteAsync(env, d, p, t, createObserver, runtimeTransport, monitoringTransport, selectedInvocation));

    internal interface SelectedInvocation
    {
        ValueTask<SecretOutcome<AzureSetSecretResult>> RunSetAsync(FixtureSelector selector,
            AzureKeyVaultClient client, AzureSetSecretRequest request, MutationReceipt receipt,
            CancellationToken cancellationToken);
    }

    internal sealed record Input(ObserverEndpoint Observer, AudienceToken Monitoring, AudienceToken DeniedMonitoring,
        Guid SubscriptionId, string ResourceGroup, string Location, Guid TenantId, Guid WorkspaceId,
        TimeSpan QueryTimeout, TimeSpan BatchTimeout, int MaximumRows, string TriggerSecretValue)
    {
        public override string ToString() => "[AuditInput]";
        internal void Validate()
        {
            Observer.Validate();
            ManagementAdmission.Require(SubscriptionId != Guid.Empty && TenantId != Guid.Empty &&
                WorkspaceId != Guid.Empty && MaximumRows is >= 1 and <= 1000 &&
                QueryTimeout >= TimeSpan.FromSeconds(1) && QueryTimeout <= TimeSpan.FromMinutes(2) &&
                BatchTimeout >= TimeSpan.FromSeconds(1) && BatchTimeout <= TimeSpan.FromMinutes(2) &&
                Monitoring.Audience == "https://api.loganalytics.io//.default" &&
                DeniedMonitoring.Audience == Monitoring.Audience && Monitoring.Token != DeniedMonitoring.Token &&
                !string.IsNullOrWhiteSpace(Monitoring.Token) && !string.IsNullOrWhiteSpace(DeniedMonitoring.Token) &&
                Monitoring.ExpiresAt > DateTimeOffset.UtcNow && DeniedMonitoring.ExpiresAt > DateTimeOffset.UtcNow &&
                !string.IsNullOrEmpty(TriggerSecretValue));
            _ = new ResourceGroupScope(new(SubscriptionId), ResourceGroup);
        }
    }
    internal enum TriggerKind { Get, List, Set, Delete, Recover, Backup, Restore, Purge, UpdateProperties }
    internal sealed record Prepare(FixtureSelector Selection, Guid SubscriptionId, string ResourceGroup,
        string Location, Guid TenantId, Guid WorkspaceId, TriggerKind TriggerOperation, int MaximumRows)
    {
        public override string ToString() => "[AuditPrepare]";
    }
    internal sealed record Window(string VaultName, string RuntimeSecretName, DateTimeOffset Start,
        DateTimeOffset End, Guid? WorkspaceId)
    {
        public override string ToString() => "[AuditWindow]";
    }
    internal sealed record Lease(LeaseFacts Facts, Window[] Windows, string TriggerId)
    {
        public override string ToString() => "[AuditLease]";
    }
    internal sealed record Trigger(Guid LeaseId, Guid Nonce, string TriggerId, TriggerKind Operation,
        string? SelectedVersion)
    {
        public override string ToString() => "[AuditTrigger]";
    }
    internal sealed record TriggerReceipt(Guid LeaseId, Guid Nonce, string TriggerId)
    {
        public override string ToString() => "[AuditTriggerReceipt]";
    }
    internal sealed record MeasuredEvent(string VaultResourceId, Guid? WorkspaceId, DateTimeOffset Timestamp,
        AuditOperation Operation, AuditResultKind Result, string TriggerId)
    {
        public override string ToString() => "[MeasuredAuditEvent]";
    }
    internal sealed record Measurement(Guid LeaseId, Guid Nonce, string ObserverIdentity,
        DateTimeOffset ObservedAt, MeasuredEvent[] Events, SecretStatus TriggerStatus)
    {
        public override string ToString() => "[AuditMeasurement]";
    }

    private static async ValueTask ExecuteAsync(OwnedAzureEnvironment env, NativeCaseDefinition definition,
        NativeCaseProbe probe, CancellationToken token, Func<ObserverEndpoint, OwnedManagementObserver>? createObserver,
        HttpPipelineTransport? runtimeTransport, HttpPipelineTransport? monitoringTransport, SelectedInvocation? selectedInvocation)
    {
        Input input = ManagementAdmission.Input<Input>(env, "AuditDiagnostics");
        input.Validate();
        FixtureSelector selection = FixtureSelector.For(definition);
        AuditOperation operation = definition.Key.Variant.StartsWith("operation.", StringComparison.Ordinal)
            ? Enum.Parse<AuditOperation>(definition.Key.Variant["operation.".Length..]) : AuditOperation.SecretSet;
        TriggerKind kind = operation switch
        {
            AuditOperation.SecretGet => TriggerKind.Get,
            AuditOperation.SecretList => TriggerKind.List,
            AuditOperation.SecretSet => TriggerKind.Set,
            AuditOperation.SecretDelete => TriggerKind.Delete,
            AuditOperation.SecretRecover => TriggerKind.Recover,
            AuditOperation.SecretBackup => TriggerKind.Backup,
            AuditOperation.SecretRestore => TriggerKind.Restore,
            AuditOperation.SecretPurge => TriggerKind.Purge,
            _ => TriggerKind.UpdateProperties
        };
        using OwnedManagementObserver service = createObserver is null ? new(input.Observer) : createObserver(input.Observer);
        LeaseFacts? known = null;
        using var eventCancellation = CancellationTokenSource.CreateLinkedTokenSource(token);
        Task<Measurement>? witness = null;
        try
        {
            Lease lease = await service.PostAsync<Prepare, Lease>("audit/prepare",
                new(selection, input.SubscriptionId, input.ResourceGroup, input.Location, input.TenantId,
                    input.WorkspaceId, kind, input.MaximumRows), token).ConfigureAwait(false);
            lease.Facts.Claim(selection);
            lease.Facts.Validate(selection, "2026-02-01");
            known = lease.Facts;
            ManagementAdmission.Require(!string.IsNullOrWhiteSpace(lease.TriggerId) &&
                lease.Windows.Length is >= 1 and <= 16);
            bool batch = definition.Key.Operation == Prefix + "QueryBatchAsync";
            int count = definition.Key.Variant is "batch.multiple" or "batch.mixed-resource-workspace" or
                "batch.caller-cancellation-progress" ? 2 : 1;
            ManagementAdmission.Require(lease.Windows.Length == count);
            var group = new ResourceGroupScope(new(input.SubscriptionId), input.ResourceGroup);
            var queries = lease.Windows.Select(w => new AuditQuery(new(group, w.VaultName), w.Start, w.End,
                input.MaximumRows, input.QueryTimeout, w.WorkspaceId)).ToArray();
            ManagementAdmission.Require(queries.All(q => lease.Facts.OwnedResourceIds.Contains(q.Vault.ExportResourceId(),
                StringComparer.OrdinalIgnoreCase)));
            if (definition.Key.Variant == "query.resource")
                ManagementAdmission.Require(queries.All(q => q.WorkspaceId is null));
            if (definition.Key.Variant == "query.workspace")
                ManagementAdmission.Require(queries.All(q => q.WorkspaceId == input.WorkspaceId));
            if (definition.Key.Variant == "batch.mixed-resource-workspace")
                ManagementAdmission.Require(queries[0].WorkspaceId is null && queries[1].WorkspaceId == input.WorkspaceId);

            // Arm the independent ingestion subscription before triggering the known
            // native vault event. This request remains pending until that exact event.
            ObservationSubscription subscription = await service.SubscribeAsync("audit", lease.Facts, token).ConfigureAwait(false);
            witness = service.PostAsync<ObserveLease, Measurement>("audit/observe",
                new(lease.Facts.LeaseId, selection.Nonce, "subscribed-event", subscription.SubscriptionId),
                eventCancellation.Token).AsTask();
            string? selectedVersion = null;
            if (kind == TriggerKind.Set)
            {
                ManagementAdmission.Require(!string.IsNullOrEmpty(input.TriggerSecretValue));
                Window window = lease.Windows[0];
                var runtime = new AzureKeyVaultClient(new("https://" + window.VaultName + ".vault.azure.net"),
                    env.Credential(NativeIdentityRole.Runtime), runtimeTransport);
                var reference = new SecretReference(runtime.Authority, new AzureSecretAddress(window.RuntimeSecretName));
                using var material = SecretMaterial.FromText(input.TriggerSecretValue);
                var receipt = new MutationReceipt(reference);
                var request = new AzureSetSecretRequest(reference, material);
                var native = selectedInvocation is null
                    ? await runtime.SetSecretAsync(request, receipt, token).ConfigureAwait(false)
                    : await selectedInvocation.RunSetAsync(selection, runtime, request, receipt, token).ConfigureAwait(false);
                AzureSetSecretResult set = ManagementAdmission.Value(native);
                ManagementAdmission.Require(receipt.Evidence == DispatchEvidence.Applied, NativeFailure.EffectMismatch);
                selectedVersion = ((AzureSecretAddress)set.Reference.Address).Version;
                ManagementAdmission.Confirm(env, definition, "selected-runtime-identity");
            }
            TriggerReceipt trigger = await service.PostAsync<Trigger, TriggerReceipt>("audit/trigger",
                new(lease.Facts.LeaseId, selection.Nonce, lease.TriggerId, kind, selectedVersion), token).ConfigureAwait(false);
            ManagementAdmission.Require(trigger.LeaseId == lease.Facts.LeaseId && trigger.Nonce == selection.Nonce &&
                trigger.TriggerId == lease.TriggerId, NativeFailure.ObserverUnavailable);
            Measurement measured = await witness.ConfigureAwait(false);
            ManagementAdmission.Require(measured.LeaseId == lease.Facts.LeaseId && measured.Nonce == selection.Nonce &&
                measured.ObserverIdentity == lease.Facts.ObserverIdentity && measured.ObservedAt >= lease.Facts.PreparedAt &&
                measured.TriggerStatus == SecretStatus.Success && measured.Events.Length > 0 &&
                measured.Events.Any(e => e.TriggerId == lease.TriggerId && e.Operation == operation),
                NativeFailure.ObserverUnavailable);

            using var http = new HttpClient(new HttpClientHandler { AllowAutoRedirect = false });
            using var cancellation = CancellationTokenSource.CreateLinkedTokenSource(token);
            string faultCase = definition.Key.Variant == "batch.caller-cancellation-progress" &&
                definition.Key.Case != "denied-authority" ? "cancellation-boundary" : definition.Key.Case;
            int seen = 0;
            var transport = new ManagementBoundaryTransport(monitoringTransport ?? new HttpClientTransport(http), faultCase, cancellation,
                _ => ++seen == (definition.Key.Variant == "batch.caller-cancellation-progress" ? 2 : 1));
            Task boundaryEvent = transport.ResponseReceived;
            using var credential = new SelectedAudienceCredential(definition.Key.Case == "denied-authority"
                ? input.DeniedMonitoring : input.Monitoring);
            var diagnostics = new AuditDiagnostics(credential, transport);
            AuditQueryResult? single = null;
            var progress = new AuditBatchProgress(queries.Length);
            bool canceled = false;
            try
            {
                if (batch)
                    await diagnostics.QueryBatchAsync(queries, progress, input.BatchTimeout, cancellation.Token).ConfigureAwait(false);
                else
                    single = await diagnostics.QueryAsync(queries[0], cancellation.Token).ConfigureAwait(false);
            }
            catch (OperationCanceledException) when (cancellation.IsCancellationRequested && !token.IsCancellationRequested)
            {
                canceled = true;
            }
            AuditQueryResult?[] results = batch ? progress.Results.ToArray() : [single];
            if (faultCase == "cancellation-boundary")
            {
                ManagementAdmission.Require(canceled && boundaryEvent.IsCompletedSuccessfully, NativeFailure.ContractMismatch);
                if (definition.Key.Variant == "batch.caller-cancellation-progress")
                {
                    ManagementAdmission.Require(progress.Results[0] is { Status: SecretStatus.Success } &&
                        progress.Results[1] is null, NativeFailure.ContractMismatch);
                    ValidateResult(progress.Results[0]!, "result.complete");
                    MatchEvents(progress.Results[0]!, queries[0], measured.Events, lease.TriggerId);
                }
            }
            else if (definition.Key.Case == "denied-authority")
                ManagementAdmission.Require(results.All(r => r is { Status: SecretStatus.Denied, Complete: false }),
                    NativeFailure.ContractMismatch);
            else
            {
                for (int index = 0; index < results.Length; index++)
                {
                    AuditQueryResult result = results[index] ?? throw new NativeCaseFailureException("contract-mismatch");
                    ValidateResult(result, definition.Key.Variant);
                    MatchEvents(result, queries[index], measured.Events, lease.TriggerId);
                }
            }
            probe.Contract(true, NativeFailure.ContractMismatch);
            // Denial/cancellation/deadline observe the independently triggered event,
            // not an invented complete query. Complete is never inferred from a partial.
            probe.Effect(NativeObservation.Matched);
            ManagementAdmission.ConfirmInfrastructure(env, definition, lease.Facts);
            if (definition.Key.Case != "denied-authority" && faultCase != "cancellation-boundary" &&
                results.All(r => r is { Status: SecretStatus.Success }))
                ManagementAdmission.Confirm(env, definition, "separate-monitoring-identity",
                    "azure-diagnostics-routing", "log-analytics-query-rights", "audit-ingestion-observer");
        }
        finally
        {
            eventCancellation.Cancel();
            if (witness is not null)
            {
                // Observe subscription shutdown on every failing trigger path.
                // The original failure remains authoritative; no worker is orphaned.
                try { await witness.ConfigureAwait(false); }
                catch (Exception) { }
            }
            await AuditFixtureRelease.ReleaseAsync(service, selection, known, probe, env, definition).ConfigureAwait(false);
        }
    }

    internal static void ValidateResult(AuditQueryResult result, string variant)
    {
        bool valid = variant switch
        {
            "result.partial-failure" => result.Status == SecretStatus.Success && !result.Complete && result.Error == AuditError.PartialFailure,
            "result.row-limit" => result.Status == SecretStatus.Success && !result.Complete && result.Error == AuditError.RowLimit,
            "result.deadline" => result.Status == SecretStatus.Unavailable && !result.Complete && result.Error == AuditError.Deadline,
            _ => result.Status == SecretStatus.Success && result.Complete && result.Error == AuditError.None
        };
        ManagementAdmission.Require(valid, NativeFailure.ContractMismatch);
    }

    internal static void MatchEvents(AuditQueryResult result, AuditQuery query, MeasuredEvent[] observed, string trigger)
    {
        MeasuredEvent[] expected = observed.Where(e =>
            e.VaultResourceId.Equals(query.Vault.ExportResourceId(), StringComparison.OrdinalIgnoreCase) &&
            e.WorkspaceId == query.WorkspaceId && e.Timestamp >= query.Start && e.Timestamp < query.End).ToArray();
        ManagementAdmission.Require(expected.Length > 0, NativeFailure.ObserverUnavailable);
        if (result.Error != AuditError.Deadline)
        {
            ManagementAdmission.Require(result.Events.Count > 0 &&
                result.Events.Any(e => expected.Any(w => w.TriggerId == trigger &&
                    w.Timestamp == e.Timestamp && w.Operation == e.Operation && w.Result == e.Result)),
                NativeFailure.EffectMismatch);
            var remaining = expected.ToList();
            foreach (AuditEvent e in result.Events)
            {
                int index = remaining.FindIndex(w =>
                    w.Timestamp == e.Timestamp && w.Operation == e.Operation && w.Result == e.Result);
                ManagementAdmission.Require(index >= 0, NativeFailure.EffectMismatch);
                remaining.RemoveAt(index);
            }
        }
        if (result.Complete)
            ManagementAdmission.Require(result.Events.Count == expected.Length, NativeFailure.EffectMismatch);
    }
}
