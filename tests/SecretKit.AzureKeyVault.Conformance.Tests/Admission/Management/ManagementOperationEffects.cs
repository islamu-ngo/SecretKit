using System.Text.Json.Serialization;
using Azure.Core.Pipeline;
using SecretKit.AzureKeyVault.Management;
using SecretKit.Core;
using SecretKit.TestFixtures;

namespace SecretKit.AzureKeyVault.Conformance.Tests.Admission.Management;

internal static class ManagementOperationEffects
{
    internal static readonly ManagementMember[] Members =
    [
        new("a.management.ManagementOperation.CheckStatusAsync",
            "SecretKit.AzureKeyVault.Management.ManagementOperation.CheckStatusAsync(System.Threading.CancellationToken)",
            ["operation.CreateOrUpdateVault", "operation.RecoverVault", "operation.DeleteVault", "operation.PurgeDeletedVault",
                "operation.UpdatePrivateConnection", "operation.DeletePrivateConnection", "operation.DeleteRoleAssignment",
                "operation.CreateOrUpdateNotification", "operation.UpdateNotification", "operation.DeleteNotification",
                "status.Pending", "status.Succeeded", "status.Failed", "status.Canceled", "status.Unknown"], false)
    ];
    internal sealed record Input(ObserverEndpoint Observer, ManagementIdentities Arm, Guid SubscriptionId,
        string ResourceGroup, string Location, Guid TenantId, VaultSku Sku, int RetentionDays,
        ManagementMutation StatusOperation, string WebhookUrl, Guid RoleAssignmentId)
    {
        public override string ToString() => "[ManagementOperationInput]";
    }
    internal sealed record Prepare(FixtureSelector Selection, Guid SubscriptionId, string ResourceGroup,
        string Location, Guid TenantId, VaultSku Sku, int RetentionDays, ManagementMutation Operation,
        string WebhookUrl, Guid RoleAssignmentId)
    {
        public override string ToString() => "[ManagementOperationPrepare]";
    }
    internal sealed record Lease(LeaseFacts Facts, string VaultName, string? PrivateConnectionName,
        string? NotificationName, Guid? RoleAssignmentId, ManagementMutation Operation,
        NativeProvisioningState ExpectedState)
    {
        public override string ToString() => "[ManagementOperationLease]";
    }
    // The service independently inspects the selected operation's native state and
    // selected resource, including absence on deletion. It does not report "passed".
    internal sealed record Measurement(Guid LeaseId, Guid Nonce, string ObserverIdentity, DateTimeOffset ObservedAt,
        ManagementMutation Operation, NativeProvisioningState OperationState, string ResourceId,
        [property: JsonRequired] SecretStatus ResourceStatus,
        [property: JsonRequired] VaultAdministrationEffects.Configuration? VaultConfiguration,
        [property: JsonRequired] PrivateConnectionState? ConnectionState,
        [property: JsonRequired] NotificationAdministrationEffects.Configuration? NotificationConfiguration)
    {
        public override string ToString() => "[ManagementOperationMeasurement]";
    }

    internal interface SelectedInvocation
    {
        ValueTask<SecretOutcome<ManagementOperation>> RunStartAsync(FixtureSelector selector,
            VaultAdministration client, ManagementScope scope, ManagementMutation operation, Input input,
            ManagementReceipt receipt, CancellationToken token);
        ValueTask<SecretStatus> RunCheckStatusAsync(FixtureSelector selector, ManagementOperation handle,
            CancellationToken token);
    }

    public static void Register(NativeCaseRegistry registry, OwnedAzureEnvironment env,
        IReadOnlyList<NativeCaseDefinition> expected, Func<ObserverEndpoint, OwnedManagementObserver>? createObserver = null,
        HttpPipelineTransport? selectedTransport = null, SelectedInvocation? selectedInvocation = null) =>
        ManagementAdmission.Register(registry, env, expected, Members,
            (d, p, t) => ExecuteAsync(env, d, p, t, createObserver, selectedTransport, selectedInvocation));

    private static bool Startable(ManagementMutation operation) => operation is
        ManagementMutation.CreateOrUpdateVault or ManagementMutation.RecoverVault or ManagementMutation.DeleteVault or
        ManagementMutation.PurgeDeletedVault or ManagementMutation.UpdatePrivateConnection or
        ManagementMutation.DeletePrivateConnection or ManagementMutation.DeleteRoleAssignment or
        ManagementMutation.CreateOrUpdateNotification or ManagementMutation.UpdateNotification or ManagementMutation.DeleteNotification;

    private static async ValueTask ExecuteAsync(OwnedAzureEnvironment env, NativeCaseDefinition definition,
        NativeCaseProbe probe, CancellationToken token, Func<ObserverEndpoint, OwnedManagementObserver>? createObserver,
        HttpPipelineTransport? selectedTransport, SelectedInvocation? selectedInvocation)
    {
        Input input = ManagementAdmission.Input<Input>(env, "ManagementOperation");
        ManagementMutation operation = definition.Key.Variant.StartsWith("operation.", StringComparison.Ordinal)
            ? Enum.Parse<ManagementMutation>(definition.Key.Variant["operation.".Length..]) : input.StatusOperation;
        ManagementAdmission.Require(Startable(operation));
        using var service = createObserver is null ? new OwnedManagementObserver(input.Observer) : createObserver(input.Observer);
        FixtureSelector selector = FixtureSelector.For(definition);
        LeaseFacts? known = null;
        try
        {
            Lease lease = await service.PostAsync<Prepare, Lease>("operation/prepare",
                new(selector, input.SubscriptionId, input.ResourceGroup, input.Location, input.TenantId, input.Sku,
                    input.RetentionDays, operation, input.WebhookUrl, input.RoleAssignmentId), token).ConfigureAwait(false);
            lease.Facts.Claim(selector);
            lease.Facts.Validate(selector, operation switch
            {
                ManagementMutation.DeleteRoleAssignment => "2022-04-01",
                ManagementMutation.CreateOrUpdateNotification or ManagementMutation.UpdateNotification or
                    ManagementMutation.DeleteNotification => "2025-02-15",
                _ => "2026-02-01"
            });
            known = lease.Facts;
            ManagementAdmission.Require(lease.Operation == operation && Enum.IsDefined(lease.ExpectedState));
            var vault = new VaultScope(new(new(input.SubscriptionId), input.ResourceGroup), lease.VaultName);
            ManagementScope scope = operation switch
            {
                ManagementMutation.PurgeDeletedVault => new DeletedVaultScope(new(input.SubscriptionId), input.Location, lease.VaultName),
                ManagementMutation.UpdatePrivateConnection or ManagementMutation.DeletePrivateConnection =>
                    new PrivateConnectionScope(vault, lease.PrivateConnectionName ?? throw new NativeCaseFailureException("missing-input")),
                ManagementMutation.DeleteRoleAssignment => new RoleAssignmentScope(vault,
                    lease.RoleAssignmentId ?? throw new NativeCaseFailureException("missing-input")),
                ManagementMutation.CreateOrUpdateNotification or ManagementMutation.UpdateNotification or ManagementMutation.DeleteNotification =>
                    new NotificationScope(vault, lease.NotificationName ?? throw new NativeCaseFailureException("missing-input")),
                _ => vault
            };
            ManagementAdmission.Require(lease.Facts.OwnedResourceIds.Contains(vault.ExportResourceId(), StringComparer.OrdinalIgnoreCase));
            // A status handle belongs to the credential/client that created it.
            // Use the denied principal to start its own operation; never hand it an
            // administrative handle and then pretend CheckStatus changes authority.
            using var clients = new ManagementClients(input.Arm, definition.Key.Case == "denied-authority"
                ? "denied-authority" : "selected-contract", token, hostTransport: selectedTransport);
            ManagementReceipt receipt = clients.Selected.PrepareReceipt(scope, operation);
            string resourceId = scope switch
            {
                VaultScope v => v.ExportResourceId(),
                DeletedVaultScope d => $"/subscriptions/{d.Subscription.SubscriptionId:D}/providers/Microsoft.KeyVault/locations/{d.Location}/deletedVaults/{d.VaultName}",
                PrivateConnectionScope c => c.Vault.ExportResourceId() + "/privateEndpointConnections/" + c.ConnectionName,
                RoleAssignmentScope r => RoleAdministrationEffects.ParentId(r.Parent) +
                    $"/providers/Microsoft.Authorization/roleAssignments/{r.AssignmentId:D}",
                NotificationScope n => n.Vault.ExportResourceId() + "/providers/Microsoft.EventGrid/eventSubscriptions/" + n.SubscriptionName,
                _ => throw new NativeCaseFailureException("contract-mismatch")
            };
            ObservationSubscription subscription = await service.SubscribeAsync("operation", lease.Facts, token).ConfigureAwait(false);
            Measurement baseline = await service.PostAsync<ObserveLease, Measurement>("operation/observe",
                new(lease.Facts.LeaseId, selector.Nonce, "baseline-before-dispatch", subscription.SubscriptionId),
                token).ConfigureAwait(false);
            ManagementAdmission.Require(baseline.LeaseId == lease.Facts.LeaseId && baseline.Nonce == selector.Nonce &&
                baseline.ObserverIdentity == lease.Facts.ObserverIdentity && baseline.ObservedAt >= subscription.ArmedAt &&
                baseline.ResourceId.Equals(resourceId, StringComparison.OrdinalIgnoreCase) &&
                baseline.Operation == operation, NativeFailure.ObserverUnavailable);
            RequireMutationBaseline(operation, input, baseline);
            SecretOutcome<ManagementOperation> started = await (selectedInvocation is null
                ? StartAsync(clients.Selected, scope, operation, input, receipt, token)
                : selectedInvocation.RunStartAsync(selector, clients.Selected, scope, operation, input, receipt, token))
                .ConfigureAwait(false);
            // A denied-status fixture must explicitly grant start rights but deny
            // the status endpoint to the same principal. Azure exposes no public
            // rebindable handle. A denied start is a missing factual prerequisite,
            // never a fabricated successful CheckStatus witness.
            if (definition.Key.Case == "denied-authority" && !started.IsSuccess)
                throw new NativeCaseFailureException("missing-prerequisite");
            ManagementOperation handle = ManagementAdmission.Value(started);
            ManagementAdmission.Receipt(receipt, "selected-contract");
            Measurement measured = await service.PostAsync<ObserveLease, Measurement>("operation/observe",
                new(lease.Facts.LeaseId, selector.Nonce, "selected-state", subscription.SubscriptionId), token).ConfigureAwait(false);
            ManagementAdmission.Require(measured.LeaseId == lease.Facts.LeaseId && measured.Nonce == selector.Nonce &&
                measured.ObserverIdentity == lease.Facts.ObserverIdentity && measured.Operation == operation &&
                measured.ObservedAt >= subscription.ArmedAt && measured.OperationState == lease.ExpectedState &&
                measured.ResourceId.Equals(resourceId, StringComparison.OrdinalIgnoreCase),
                NativeFailure.ObserverUnavailable);
            SecretStatus status;
            if (definition.Key.Case == "cancellation-boundary")
            {
                // The independent selected-state subscription above is the exact
                // barrier before cancellation, including already completed LROs.
                using var canceled = new CancellationTokenSource();
                canceled.Cancel();
                bool propagated = false;
                try { await CheckStatusAsync(canceled.Token).ConfigureAwait(false); }
                catch (OperationCanceledException) { propagated = true; }
                ManagementAdmission.Require(propagated, NativeFailure.ContractMismatch);
                status = await CheckStatusAsync(token).ConfigureAwait(false);
            }
            else
                status = await CheckStatusAsync(token).ConfigureAwait(false);
            ValueTask<SecretStatus> CheckStatusAsync(CancellationToken cancellation) => selectedInvocation is null
                ? handle.CheckStatusAsync(cancellation)
                : selectedInvocation.RunCheckStatusAsync(selector, handle, cancellation);
            if (definition.Key.Case == "denied-authority")
            {
                ManagementAdmission.Require(status == SecretStatus.Denied, NativeFailure.ContractMismatch);
                probe.Contract(true, NativeFailure.ContractMismatch);
                probe.Effect(NativeObservation.Matched);
                ManagementAdmission.ConfirmInfrastructure(env, definition, lease.Facts);
                return;
            }
            NativeProvisioningState expectedState = definition.Key.Variant.StartsWith("status.", StringComparison.Ordinal)
                ? Enum.Parse<NativeProvisioningState>(definition.Key.Variant["status.".Length..]) : lease.ExpectedState;
            ManagementAdmission.Require(expectedState == measured.OperationState && handle.State == expectedState &&
                status == (expectedState switch
                {
                    NativeProvisioningState.Succeeded => SecretStatus.Success,
                    NativeProvisioningState.Pending => SecretStatus.Pending,
                    _ => SecretStatus.Unknown
                }), NativeFailure.ContractMismatch);
            bool deleting = operation is ManagementMutation.DeleteVault or ManagementMutation.PurgeDeletedVault or
                ManagementMutation.DeletePrivateConnection or ManagementMutation.DeleteRoleAssignment or ManagementMutation.DeleteNotification;
            ManagementAdmission.Require(measured.ResourceStatus ==
                (deleting && expectedState == NativeProvisioningState.Succeeded ? SecretStatus.Absent : SecretStatus.Success),
                NativeFailure.EffectMismatch);
            if (expectedState == NativeProvisioningState.Succeeded)
                ValidatePersistedState(operation, input, measured);
            probe.Contract(true, NativeFailure.ContractMismatch);
            probe.Effect(NativeObservation.Matched);
            ManagementAdmission.ConfirmInfrastructure(env, definition, lease.Facts);
            ManagementAdmission.Confirm(env, definition, "selected-administrative-identity",
                "scoped-administrative-rights", "azure-arm-public-cloud-rights");
        }
        finally
        {
            await ManagementOperationFixtureRelease.ReleaseAsync(service, selector, known, probe, env, definition).ConfigureAwait(false);
        }
    }

    internal static void RequireMutationBaseline(ManagementMutation operation, Input input, Measurement baseline)
    {
        bool valid = operation switch
        {
            ManagementMutation.CreateOrUpdateVault => baseline.ResourceStatus == SecretStatus.Absent ||
                baseline.ResourceStatus == SecretStatus.Success && baseline.VaultConfiguration is { } configuration &&
                !VaultAdministrationEffects.SameConfiguration(configuration, ExpectedVault(input)),
            ManagementMutation.RecoverVault => baseline.ResourceStatus == SecretStatus.Absent,
            ManagementMutation.UpdatePrivateConnection => baseline.ResourceStatus == SecretStatus.Success &&
                baseline.ConnectionState is not null && baseline.ConnectionState != PrivateConnectionState.Approved,
            ManagementMutation.CreateOrUpdateNotification => baseline.ResourceStatus == SecretStatus.Absent ||
                baseline.ResourceStatus == SecretStatus.Success && baseline.NotificationConfiguration is { } configuration &&
                !NotificationAdministrationEffects.SameConfiguration(configuration, ExpectedNotification(input)),
            ManagementMutation.UpdateNotification => baseline.ResourceStatus == SecretStatus.Success &&
                baseline.NotificationConfiguration is { } configuration &&
                !NotificationAdministrationEffects.SameConfiguration(configuration, ExpectedNotification(input)),
            _ => baseline.ResourceStatus == SecretStatus.Success
        };
        ManagementAdmission.Require(valid, NativeFailure.MissingPrerequisite);
    }

    private static VaultAdministrationEffects.Configuration ExpectedVault(Input input) =>
        new(input.Location, input.TenantId, input.Sku, true, false, input.RetentionDays, true, []);

    private static NotificationAdministrationEffects.Configuration ExpectedNotification(Input input) =>
        new(input.WebhookUrl, [VaultNotificationEvent.SecretNewVersionCreated], null);

    internal static void ValidatePersistedState(ManagementMutation operation, Input input, Measurement measured)
    {
        bool valid = operation switch
        {
            ManagementMutation.CreateOrUpdateVault or ManagementMutation.RecoverVault =>
                measured.VaultConfiguration is { } configuration &&
                VaultAdministrationEffects.SameConfiguration(configuration, ExpectedVault(input)),
            ManagementMutation.UpdatePrivateConnection => measured.ConnectionState == PrivateConnectionState.Approved,
            ManagementMutation.CreateOrUpdateNotification or ManagementMutation.UpdateNotification =>
                measured.NotificationConfiguration is { } configuration &&
                NotificationAdministrationEffects.SameConfiguration(configuration, ExpectedNotification(input)),
            _ => measured.ResourceStatus == SecretStatus.Absent
        };
        ManagementAdmission.Require(valid, NativeFailure.EffectMismatch);
    }

    internal static ValueTask<SecretOutcome<ManagementOperation>> StartAsync(VaultAdministration client,
        ManagementScope scope, ManagementMutation operation, Input input, ManagementReceipt receipt, CancellationToken token)
    {
        switch (operation)
        {
            case ManagementMutation.CreateOrUpdateVault:
                return client.CreateOrUpdateVaultAsync((VaultScope)scope,
                    new(input.Location, input.TenantId, input.Sku, true, false, input.RetentionDays, true), receipt, token);
            case ManagementMutation.RecoverVault:
                return client.RecoverVaultAsync((VaultScope)scope,
                    new(input.Location, input.TenantId, input.Sku, true, false, input.RetentionDays, true), receipt, token);
            case ManagementMutation.DeleteVault:
                return client.DeleteVaultAsync((VaultScope)scope, receipt, token);
            case ManagementMutation.PurgeDeletedVault:
                return client.PurgeDeletedVaultAsync((DeletedVaultScope)scope, receipt, token);
            case ManagementMutation.UpdatePrivateConnection:
                return client.UpdatePrivateConnectionAsync((PrivateConnectionScope)scope, PrivateConnectionState.Approved, receipt, token);
            case ManagementMutation.DeletePrivateConnection:
                return client.DeletePrivateConnectionAsync((PrivateConnectionScope)scope, receipt, token);
            case ManagementMutation.DeleteRoleAssignment:
                return client.DeleteRoleAssignmentAsync((RoleAssignmentScope)scope, receipt, token);
            case ManagementMutation.CreateOrUpdateNotification:
            case ManagementMutation.UpdateNotification:
                return StartNotificationAsync(client, (NotificationScope)scope, operation, input.WebhookUrl, receipt, token);
            case ManagementMutation.DeleteNotification:
                return client.DeleteNotificationAsync((NotificationScope)scope, receipt, token);
            default:
                throw new NativeCaseFailureException("missing-input");
        }
    }

    private static async ValueTask<SecretOutcome<ManagementOperation>> StartNotificationAsync(VaultAdministration client,
        NotificationScope scope, ManagementMutation operation, string endpoint, ManagementReceipt receipt, CancellationToken token)
    {
        using var configuration = new NotificationConfiguration(endpoint, [VaultNotificationEvent.SecretNewVersionCreated]);
        return operation == ManagementMutation.CreateOrUpdateNotification
            ? await client.CreateOrUpdateNotificationAsync(scope, configuration, receipt, token).ConfigureAwait(false)
            : await client.UpdateNotificationAsync(scope, configuration, receipt, token).ConfigureAwait(false);
    }
}
