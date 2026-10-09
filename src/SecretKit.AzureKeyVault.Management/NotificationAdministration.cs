using Azure;
using Azure.Core;
using Azure.ResourceManager.EventGrid;
using Azure.ResourceManager.EventGrid.Models;
using SecretKit.Core;

namespace SecretKit.AzureKeyVault.Management;

public sealed partial class VaultAdministration
{
    private const string NotificationRevision = "2025-02-15";

    public ValueTask<SecretOutcome<NotificationObservation>> GetNotificationAsync(NotificationScope scope,
        CancellationToken cancellationToken = default)
    {
        ArgumentNullException.ThrowIfNull(scope);
        return Read(scope.ResourceId, async (client, token) => ObserveNotification(scope,
            (await client.GetEventSubscriptionResource(new ResourceIdentifier(scope.ResourceId))
                .GetAsync(token).ConfigureAwait(false)).Value.Data),
            cancellationToken, revision: NotificationRevision);
    }

    public ValueTask<ManagementInventory<NotificationObservation>> ListNotificationsAsync(VaultScope scope,
        CollectionLimits limits, CancellationToken cancellationToken = default)
    {
        ArgumentNullException.ThrowIfNull(scope);
        return Collect($"{scope.ResourceId}/providers/Microsoft.EventGrid/eventSubscriptions", limits,
            (client, token) => client.GetEventSubscriptions(new ResourceIdentifier(scope.ResourceId))
                .GetAllAsync(cancellationToken: token),
            resource => ObserveNotification(new NotificationScope(scope, resource.Data.Name), resource.Data),
            cancellationToken, NotificationRevision);
    }

    public ValueTask<SecretOutcome<NotificationFullUrl>> GetNotificationFullUrlAsync(NotificationScope scope,
        CancellationToken cancellationToken = default)
    {
        ArgumentNullException.ThrowIfNull(scope);
        return Read(scope.ResourceId + "/getFullUrl", async (client, token) =>
            new NotificationFullUrl((await client.GetEventSubscriptionResource(new ResourceIdentifier(scope.ResourceId))
                .GetFullUriAsync(token).ConfigureAwait(false)).Value.Endpoint),
            cancellationToken, revision: NotificationRevision, method: RequestMethod.Post);
    }

    public ValueTask<ManagementInventory<NotificationDeliveryAttribute>> GetNotificationDeliveryAttributesAsync(
        NotificationScope scope, CollectionLimits limits, CancellationToken cancellationToken = default)
    {
        ArgumentNullException.ThrowIfNull(scope);
        return Collect(scope.ResourceId + "/getDeliveryAttributes", limits,
            (client, token) => client.GetEventSubscriptionResource(new ResourceIdentifier(scope.ResourceId))
                .GetDeliveryAttributesAsync(token), attribute => attribute switch
                {
                    StaticDeliveryAttributeMapping value when value.Value is not null =>
                        new NotificationDeliveryAttribute(value.Name, NotificationAttributeKind.Static, value.Value,
                            value.IsSecret ?? true),
                    DynamicDeliveryAttributeMapping value when value.SourceField is not null =>
                        new NotificationDeliveryAttribute(value.Name, NotificationAttributeKind.Dynamic, value.SourceField),
                    _ => throw new ControlledTransport.BoundaryException()
                }, cancellationToken, NotificationRevision, RequestMethod.Post);
    }

    /// <summary>Explicit webhook create/update subset, not CAS or conditional creation.</summary>
    public ValueTask<SecretOutcome<ManagementOperation>> CreateOrUpdateNotificationAsync(NotificationScope scope,
        NotificationConfiguration configuration, ManagementReceipt receipt, CancellationToken cancellationToken = default)
    {
        ArgumentNullException.ThrowIfNull(scope);
        ArgumentNullException.ThrowIfNull(configuration);
        return Mutate(scope, ManagementMutation.CreateOrUpdateNotification, receipt, scope.ResourceId, RequestMethod.Put,
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
            }, cancellationToken, NotificationRevision);
    }

    /// <summary>Replaces webhook destination and secret-event filter only; other native settings are omitted.</summary>
    public ValueTask<SecretOutcome<ManagementOperation>> UpdateNotificationAsync(NotificationScope scope,
        NotificationConfiguration configuration, ManagementReceipt receipt, CancellationToken cancellationToken = default)
    {
        ArgumentNullException.ThrowIfNull(scope);
        ArgumentNullException.ThrowIfNull(configuration);
        return Mutate(scope, ManagementMutation.UpdateNotification, receipt, scope.ResourceId, RequestMethod.Patch,
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
            }, cancellationToken, NotificationRevision);
    }

    public ValueTask<SecretOutcome<ManagementOperation>> DeleteNotificationAsync(NotificationScope scope,
        ManagementReceipt receipt, CancellationToken cancellationToken = default)
    {
        ArgumentNullException.ThrowIfNull(scope);
        return Mutate(scope, ManagementMutation.DeleteNotification, receipt, scope.ResourceId, RequestMethod.Delete,
            [200, 202, 204], async (client, transport, token) =>
            {
                var operation = await client.GetEventSubscriptionResource(new ResourceIdentifier(scope.ResourceId))
                    .DeleteAsync(WaitUntil.Started, token).ConfigureAwait(false);
                return transport.LastStatus is 200 or 204
                    ? ManagementOperation.Completed(transport, _timeout, _time)
                    : ManagementOperation.From(operation, transport, _timeout, _time);
            },
            cancellationToken, NotificationRevision);
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
        return new(scope, Provisioning(data.ProvisioningState?.ToString()), data.Destination switch
        {
            WebHookEventSubscriptionDestination => NotificationDestinationKind.WebHook,
            null => NotificationDestinationKind.Unknown,
            _ => NotificationDestinationKind.Other
        });
    }
}
