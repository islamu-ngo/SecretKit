using Azure;
using Azure.Core;
using Azure.ResourceManager.EventGrid;
using Azure.ResourceManager.EventGrid.Models;
using SecretKit.Core;

namespace SecretKit.AzureKeyVault.Management;

public sealed partial class VaultAdministration
{

    /// <summary>Reads bounded notification metadata without exporting its full endpoint or delivery attributes.</summary>
    /// <param name="scope">The exact vault event-subscription coordinates.</param>
    /// <param name="cancellationToken">Cancels the read and propagates caller cancellation.</param>
    /// <returns>Validated subscription metadata, not proof of event delivery, or a bounded failure.</returns>
    /// <exception cref="ArgumentNullException">The scope is null.</exception>
    /// <exception cref="OperationCanceledException">Caller cancellation was observed.</exception>
    public ValueTask<SecretOutcome<NotificationObservation>> GetNotificationAsync(NotificationScope scope,
        CancellationToken cancellationToken = default)
    {
        ArgumentNullException.ThrowIfNull(scope);
        return Read(ArmCallTarget.At(ArmMethodContracts.NotificationGet, scope), async (client, token) => ObserveNotification(scope,
            (await client.GetEventSubscriptionResource(new ResourceIdentifier(scope.ResourceId))
                .GetAsync(token).ConfigureAwait(false)).Value.Data),
            cancellationToken);
    }

    /// <summary>Collects bounded notification metadata for one vault without exporting destinations.</summary>
    /// <param name="scope">The selected vault.</param>
    /// <param name="limits">Local enumeration budgets.</param>
    /// <param name="cancellationToken">Cancels collection and propagates caller cancellation.</param>
    /// <returns>Copied observations and explicit completeness, not a delivery test.</returns>
    /// <exception cref="ArgumentNullException">The scope or limits is null.</exception>
    /// <exception cref="OperationCanceledException">Caller cancellation was observed.</exception>
    public ValueTask<ManagementInventory<NotificationObservation>> ListNotificationsAsync(VaultScope scope,
        CollectionLimits limits, CancellationToken cancellationToken = default)
    {
        ArgumentNullException.ThrowIfNull(scope);
        return Collect(ArmCallTarget.Below(ArmMethodContracts.NotificationList, scope), limits,
            (client, token) => client.GetEventSubscriptions(new ResourceIdentifier(scope.ResourceId))
                .GetAllAsync(cancellationToken: token),
            resource => ObserveNotification(new NotificationScope(scope, resource.Data.Name), resource.Data),
            cancellationToken);
    }

    /// <summary>Explicitly acquires protected full webhook endpoint material through the native read action.</summary>
    /// <param name="scope">The exact notification subscription.</param>
    /// <param name="cancellationToken">Cancels acquisition; unpublished owned results are disposed.</param>
    /// <returns>A full-URL owner the caller must dispose, or a bounded failure.</returns>
    /// <exception cref="ArgumentNullException">The scope is null.</exception>
    /// <exception cref="OperationCanceledException">Caller cancellation was observed.</exception>
    public ValueTask<SecretOutcome<NotificationFullUrl>> GetNotificationFullUrlAsync(NotificationScope scope,
        CancellationToken cancellationToken = default)
    {
        ArgumentNullException.ThrowIfNull(scope);
        return Read(ArmCallTarget.Below(ArmMethodContracts.NotificationGetFullUrl, scope), async (client, token) =>
            new NotificationFullUrl((await client.GetEventSubscriptionResource(new ResourceIdentifier(scope.ResourceId))
                .GetFullUriAsync(token).ConfigureAwait(false)).Value.Endpoint),
            cancellationToken, method: RequestMethod.Post);
    }

    /// <summary>Explicitly acquires bounded protected delivery attributes using the native read action.</summary>
    /// <param name="scope">The exact notification subscription.</param>
    /// <param name="limits">Local enumeration budgets.</param>
    /// <param name="cancellationToken">Cancels collection and propagates caller cancellation.</param>
    /// <returns>An inventory whose every returned attribute the caller must dispose, including partial inventories.</returns>
    /// <exception cref="ArgumentNullException">The scope or limits is null.</exception>
    /// <exception cref="OperationCanceledException">Caller cancellation was observed; unpublished owned attributes are disposed.</exception>
    public ValueTask<ManagementInventory<NotificationDeliveryAttribute>> GetNotificationDeliveryAttributesAsync(
        NotificationScope scope, CollectionLimits limits, CancellationToken cancellationToken = default)
    {
        ArgumentNullException.ThrowIfNull(scope);
        return Collect(ArmCallTarget.Below(ArmMethodContracts.NotificationGetDeliveryAttributes, scope), limits,
            (client, token) => client.GetEventSubscriptionResource(new ResourceIdentifier(scope.ResourceId))
                .GetDeliveryAttributesAsync(token), attribute => attribute switch
                {
                    StaticDeliveryAttributeMapping value when value.Value is not null =>
                        new NotificationDeliveryAttribute(value.Name, NotificationAttributeKind.Static, value.Value,
                            value.IsSecret ?? true),
                    DynamicDeliveryAttributeMapping value when value.SourceField is not null =>
                        new NotificationDeliveryAttribute(value.Name, NotificationAttributeKind.Dynamic, value.SourceField),
                    _ => throw new ControlledTransport.BoundaryException()
                }, cancellationToken, RequestMethod.Post);
    }

    /// <summary>Explicit webhook create/update subset, not CAS or conditional creation.</summary>
    /// <param name="scope">The exact subscription to create or replace.</param>
    /// <param name="configuration">Caller-owned endpoint/filter configuration retained through execution.</param>
    /// <param name="receipt">Unused client-prepared evidence for this scope and CreateOrUpdateNotification.</param>
    /// <param name="cancellationToken">Cancels locally without undoing a dispatched effect.</param>
    /// <returns>An operation for explicit status checks, or a bounded failure; no event delivery is proven.</returns>
    /// <exception cref="ArgumentNullException">The scope, configuration or receipt is null.</exception>
    /// <exception cref="OperationCanceledException">Caller cancellation was observed; retain and inspect the receipt.</exception>
    public ValueTask<SecretOutcome<ManagementOperation>> CreateOrUpdateNotificationAsync(NotificationScope scope,
        NotificationConfiguration configuration, ManagementReceipt receipt, CancellationToken cancellationToken = default)
    {
        ArgumentNullException.ThrowIfNull(scope);
        ArgumentNullException.ThrowIfNull(configuration);
        return Mutate(scope, ManagementMutation.CreateOrUpdateNotification, receipt, ArmCallTarget.At(ArmMethodContracts.NotificationCreateOrUpdate, scope), RequestMethod.Put,
            [201], async (client, transport, token) =>
            {
                var data = new EventGridSubscriptionData
                {
                    Destination = configuration.Destination(),
                    Filter = configuration.Filter()
                };
                var operation = await client.GetEventSubscriptions(new ResourceIdentifier(scope.Vault.ResourceId))
                    .CreateOrUpdateAsync(WaitUntil.Started, scope.SubscriptionName, data, token).ConfigureAwait(false);
                bool Validate() => operation.HasValue &&
                    ObserveNotification(scope, operation.Value.Data).ProvisioningState == NativeProvisioningState.Succeeded;
                return NotificationOperation(scope, operation, transport, Validate);
            }, cancellationToken);
    }

    /// <summary>Replaces webhook destination and secret-event filter only; other native settings are omitted.</summary>
    /// <param name="scope">The exact existing subscription.</param>
    /// <param name="configuration">Caller-owned replacement destination and filter retained through execution.</param>
    /// <param name="receipt">Unused client-prepared evidence for this scope and UpdateNotification.</param>
    /// <param name="cancellationToken">Cancels locally without proving that an update did not occur.</param>
    /// <returns>An operation for explicit status checks, or a bounded failure without replay.</returns>
    /// <exception cref="ArgumentNullException">The scope, configuration or receipt is null.</exception>
    /// <exception cref="OperationCanceledException">Caller cancellation was observed; retain and inspect the receipt.</exception>
    public ValueTask<SecretOutcome<ManagementOperation>> UpdateNotificationAsync(NotificationScope scope,
        NotificationConfiguration configuration, ManagementReceipt receipt, CancellationToken cancellationToken = default)
    {
        ArgumentNullException.ThrowIfNull(scope);
        ArgumentNullException.ThrowIfNull(configuration);
        return Mutate(scope, ManagementMutation.UpdateNotification, receipt, ArmCallTarget.At(ArmMethodContracts.NotificationUpdate, scope), RequestMethod.Patch,
            [201], async (client, transport, token) =>
            {
                var patch = new EventGridSubscriptionPatch
                {
                    Destination = configuration.Destination(),
                    Filter = configuration.Filter()
                };
                var operation = await client.GetEventSubscriptionResource(new ResourceIdentifier(scope.ResourceId))
                    .UpdateAsync(WaitUntil.Started, patch, token).ConfigureAwait(false);
                bool Validate() => operation.HasValue &&
                    ObserveNotification(scope, operation.Value.Data).ProvisioningState == NativeProvisioningState.Succeeded;
                return NotificationOperation(scope, operation, transport, Validate);
            }, cancellationToken);
    }

    /// <summary>Deletes one notification subscription without automatic replay or a background completion loop.</summary>
    /// <param name="scope">The exact subscription to delete.</param>
    /// <param name="receipt">Unused client-prepared evidence for this scope and DeleteNotification.</param>
    /// <param name="cancellationToken">Cancels locally; dispatched deletion may still take effect.</param>
    /// <returns>A completed or pending local operation handle, or a bounded failure.</returns>
    /// <exception cref="ArgumentNullException">The scope or receipt is null.</exception>
    /// <exception cref="OperationCanceledException">Caller cancellation was observed; retain and inspect the receipt.</exception>
    public ValueTask<SecretOutcome<ManagementOperation>> DeleteNotificationAsync(NotificationScope scope,
        ManagementReceipt receipt, CancellationToken cancellationToken = default)
    {
        ArgumentNullException.ThrowIfNull(scope);
        return Mutate(scope, ManagementMutation.DeleteNotification, receipt, ArmCallTarget.At(ArmMethodContracts.NotificationDelete, scope), RequestMethod.Delete,
            [200, 202, 204], async (client, transport, token) =>
            {
                var operation = await client.GetEventSubscriptionResource(new ResourceIdentifier(scope.ResourceId))
                    .DeleteAsync(WaitUntil.Started, token).ConfigureAwait(false);
                return transport.LastStatus is 200 or 204
                    ? ManagementOperation.Completed(transport, _timeout, _time)
                    : ManagementOperation.From(operation, transport, _timeout, _time);
            },
            cancellationToken);
    }

    private ManagementOperation NotificationOperation(NotificationScope scope,
        Azure.ResourceManager.ArmOperation<EventSubscriptionResource> operation, ControlledTransport transport,
        Func<bool> validate)
    {
        if (operation.HasValue)
        {
            var state = ObserveNotification(scope, operation.Value.Data).ProvisioningState;
            if (state is NativeProvisioningState.Unknown or NativeProvisioningState.Failed or NativeProvisioningState.Canceled ||
                (operation.HasCompleted && state != NativeProvisioningState.Succeeded))
                throw new ControlledTransport.BoundaryException();
        }
        if (operation.HasCompleted && !validate()) throw new ControlledTransport.BoundaryException();
        return ManagementOperation.From(operation, transport, _timeout, _time, validate);
    }

    private static NotificationObservation ObserveNotification(NotificationScope scope, EventGridSubscriptionData data)
    {
        if (!Same(data.Id, scope.ResourceId) ||
            !string.Equals(data.Name, scope.SubscriptionName, StringComparison.OrdinalIgnoreCase) ||
            !string.Equals(data.Topic, scope.Vault.ResourceId, StringComparison.OrdinalIgnoreCase))
            throw new ControlledTransport.BoundaryException();
        NotificationWebhookAuthentication? authentication = null;
        if (data.Destination is WebHookEventSubscriptionDestination webhook)
        {
            var tenant = webhook.AzureActiveDirectoryTenantId;
            var audience = webhook.UriOrAzureActiveDirectoryApplicationId;
            if (tenant.HasValue != (audience is not null))
                throw new ControlledTransport.BoundaryException();
            if (tenant is { } tenantId && audience is not null)
                authentication = new NotificationWebhookAuthentication(tenantId, audience);
        }
        return new(scope, Provisioning(data.ProvisioningState?.ToString()), data.Destination switch
        {
            WebHookEventSubscriptionDestination => NotificationDestinationKind.WebHook,
            null => NotificationDestinationKind.Unknown,
            _ => NotificationDestinationKind.Other
        }, authentication);
    }
}
