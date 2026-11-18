namespace SecretKit.AzureKeyVault.Management;

public sealed partial class VaultAdministration
{
    /// <summary>Collects subscription metadata under the selected administrative identity without testing secret access.</summary>
    /// <param name="limits">Local page, item and time budgets; null selects the default finite limits.</param>
    /// <param name="cancellationToken">Cancels enumeration and propagates caller cancellation.</param>
    /// <returns>Validated observations in provider page order with explicit completeness and bounded failure status.</returns>
    /// <exception cref="OperationCanceledException">Caller cancellation was observed.</exception>
    public ValueTask<ManagementInventory<SubscriptionObservation>> ListSubscriptionsAsync(
        CollectionLimits? limits = null, CancellationToken cancellationToken = default) =>
        Collect("/subscriptions", limits ?? new CollectionLimits(),
            (client, token) => client.GetSubscriptions().GetAllAsync(token),
            resource => new SubscriptionObservation(resource.Data), cancellationToken, revision: "2022-12-01");
}
