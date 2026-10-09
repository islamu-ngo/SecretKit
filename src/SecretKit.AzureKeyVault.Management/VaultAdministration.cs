using Azure;
using Azure.Core;
using Azure.Core.Pipeline;
using Azure.ResourceManager;
using Azure.ResourceManager.KeyVault;
using Azure.ResourceManager.KeyVault.Models;
using Azure.ResourceManager.Resources;
using SecretKit.Core;

namespace SecretKit.AzureKeyVault.Management;

/// <summary>
/// Azure public cloud only, Key Vault ARM 2026-02-01. Explicit administration identity,
/// host-owned transport, no data-plane access and no runtime delivery proof.
/// </summary>
public sealed partial class VaultAdministration
{
    private const string Revision = "2026-02-01";
    private readonly TokenCredential _credential;
    private readonly HttpPipelineTransport _transport;
    private readonly int _maximumBytes;
    private readonly TimeSpan _timeout;
    private readonly TimeProvider _time;
    private readonly SecretAuthority _authority = new();

    public VaultAdministration(TokenCredential administrativeCredential, HttpPipelineTransport transport,
        int maximumResponseBytes = 1024 * 1024, TimeSpan? timeout = null, TimeProvider? timeProvider = null)
    {
        ArgumentNullException.ThrowIfNull(administrativeCredential);
        ArgumentNullException.ThrowIfNull(transport);
        if (maximumResponseBytes is < 1024 or > 16 * 1024 * 1024)
        {
            throw new ArgumentOutOfRangeException(nameof(maximumResponseBytes));
        }

        _credential = administrativeCredential;
        _transport = transport;
        _maximumBytes = maximumResponseBytes;
        _timeout = timeout ?? TimeSpan.FromSeconds(30);
        if (_timeout <= TimeSpan.Zero || _timeout > TimeSpan.FromMinutes(2))
        {
            throw new ArgumentOutOfRangeException(nameof(timeout));
        }

        _time = timeProvider ?? TimeProvider.System;
    }

    public ManagementReceipt PrepareReceipt(ManagementScope scope, ManagementMutation operation)
    {
        ArgumentNullException.ThrowIfNull(scope);
        bool valid = operation switch
        {
            ManagementMutation.CreateOrUpdateVault or ManagementMutation.RecoverVault or
            ManagementMutation.UpdateVault or ManagementMutation.DeleteVault or
            ManagementMutation.AddAccessPolicy or ManagementMutation.ReplaceAccessPolicy or
            ManagementMutation.RemoveAccessPolicy => scope is VaultScope,
            ManagementMutation.PurgeDeletedVault => scope is DeletedVaultScope,
            ManagementMutation.UpdatePrivateConnection or ManagementMutation.DeletePrivateConnection =>
                scope is PrivateConnectionScope,
            ManagementMutation.CreateRoleAssignment or ManagementMutation.DeleteRoleAssignment =>
                scope is RoleAssignmentScope { Parent: VaultScope },
            ManagementMutation.CreateOrUpdateNotification or ManagementMutation.UpdateNotification or
                ManagementMutation.DeleteNotification => scope is NotificationScope,
            _ => false
        };
        return valid ? new ManagementReceipt(_authority, scope, operation) :
            throw new ArgumentException("Scope does not match the native operation.");
    }

    private ArmClient Client(string path, RequestMethod method, int[] statuses,
        out ControlledTransport transport, ManagementReceipt? receipt = null, string revision = Revision)
    {
        transport = new ControlledTransport(_transport, "management.azure.com", path, method, revision,
            statuses, _maximumBytes, receipt);
        var options = new ArmClientOptions
        {
            Environment = new ArmEnvironment(new Uri("https://management.azure.com"), "https://management.azure.com"),
            Transport = transport
        };
        options.Diagnostics.IsLoggingEnabled = false;
        options.Diagnostics.IsLoggingContentEnabled = false;
        options.Diagnostics.IsDistributedTracingEnabled = false;
        options.Retry.MaxRetries = 0;
        foreach (string resourceType in new[]
        {
            "Microsoft.KeyVault/vaults", "Microsoft.KeyVault/deletedVaults",
            "Microsoft.KeyVault/vaults/privateEndpointConnections", "Microsoft.KeyVault/vaults/privateLinkResources",
            "Microsoft.Authorization/roleAssignments", "Microsoft.Authorization/roleDefinitions",
            "Microsoft.EventGrid/eventSubscriptions"
        })
        {
            options.SetApiVersion(resourceType, revision);
        }

        return new ArmClient(_credential, null, options);
    }

    private async ValueTask<SecretOutcome<T>> Read<T>(string path, Func<ArmClient, CancellationToken, Task<T>> read,
        CancellationToken cancellationToken, int[]? statuses = null, string revision = Revision,
        RequestMethod? method = null) where T : notnull
    {
        using var deadline = new CancellationTokenSource(_timeout, _time);
        using var linked = CancellationTokenSource.CreateLinkedTokenSource(cancellationToken, deadline.Token);
        cancellationToken.ThrowIfCancellationRequested();
        var client = Client(path, method ?? RequestMethod.Get, statuses ?? [200], out var transport, revision: revision);
        T? value = default;
        try
        {
            value = await read(client, linked.Token).ConfigureAwait(false);
            cancellationToken.ThrowIfCancellationRequested();
            if (transport.LastStatus == 204)
            {
                return SecretOutcome<T>.Failure(SecretStatus.Absent);
            }

            return SecretOutcome<T>.Success(value);
        }
        catch (OperationCanceledException)
        {
            if (value is NotificationFullUrl fullUrl) fullUrl.Dispose();
            cancellationToken.ThrowIfCancellationRequested();
            return SecretOutcome<T>.Failure(SecretStatus.Unavailable);
        }
        catch (Exception exception)
        {
            cancellationToken.ThrowIfCancellationRequested();
            if (transport.LastStatus == 204)
            {
                return SecretOutcome<T>.Failure(SecretStatus.Absent);
            }

            return SecretOutcome<T>.Failure(ControlledTransport.Failure(exception));
        }
    }

    public ValueTask<SecretOutcome<VaultObservation>> GetVaultAsync(VaultScope scope,
        CancellationToken cancellationToken = default)
    {
        ArgumentNullException.ThrowIfNull(scope);
        return Read(scope.ResourceId, async (client, token) => Observe(scope,
            (await client.GetKeyVaultResource(new ResourceIdentifier(scope.ResourceId)).GetAsync(token)
                .ConfigureAwait(false)).Value.Data), cancellationToken);
    }

    public ValueTask<SecretOutcome<DeletedVaultObservation>> GetDeletedVaultAsync(DeletedVaultScope scope,
        CancellationToken cancellationToken = default)
    {
        ArgumentNullException.ThrowIfNull(scope);
        return Read(scope.ResourceId, async (client, token) => ObserveDeleted(scope,
            (await client.GetDeletedKeyVaultResource(new ResourceIdentifier(scope.ResourceId)).GetAsync(token)
                .ConfigureAwait(false)).Value.Data), cancellationToken);
    }

    public async ValueTask<SecretOutcome<VaultNameAvailability>> CheckNameAvailabilityAsync(
        SubscriptionScope subscription, string vaultName, CancellationToken cancellationToken = default)
    {
        ArgumentNullException.ThrowIfNull(subscription);
        VaultScope.ValidateName(vaultName);
        using var deadline = new CancellationTokenSource(_timeout, _time);
        using var linked = CancellationTokenSource.CreateLinkedTokenSource(cancellationToken, deadline.Token);
        cancellationToken.ThrowIfCancellationRequested();
        try
        {
            var client = Client($"{subscription.ResourceId}/providers/Microsoft.KeyVault/checkNameAvailability",
                RequestMethod.Post, [200], out _);
            var response = await client.GetSubscriptionResource(new ResourceIdentifier(subscription.ResourceId))
                .CheckKeyVaultNameAvailabilityAsync(new KeyVaultNameAvailabilityContent(vaultName), linked.Token)
                .ConfigureAwait(false);
            return SecretOutcome<VaultNameAvailability>.Success(new(response.Value.NameAvailable));
        }
        catch (OperationCanceledException)
        {
            cancellationToken.ThrowIfCancellationRequested();
            return SecretOutcome<VaultNameAvailability>.Failure(SecretStatus.Unavailable);
        }
        catch (Exception exception)
        {
            cancellationToken.ThrowIfCancellationRequested();
            return SecretOutcome<VaultNameAvailability>.Failure(ControlledTransport.Failure(exception));
        }
    }

    /// <summary>Explicit create/update, not conditional create. Recover uses native createMode, not empty creation.</summary>
    public ValueTask<SecretOutcome<ManagementOperation>> CreateOrUpdateVaultAsync(VaultScope scope,
        VaultConfiguration configuration, ManagementReceipt receipt, CancellationToken cancellationToken = default) =>
        CreateVault(scope, configuration, receipt, false, cancellationToken);

    public ValueTask<SecretOutcome<ManagementOperation>> RecoverVaultAsync(VaultScope scope,
        VaultConfiguration configuration, ManagementReceipt receipt, CancellationToken cancellationToken = default) =>
        CreateVault(scope, configuration, receipt, true, cancellationToken);

    private ValueTask<SecretOutcome<ManagementOperation>> CreateVault(VaultScope scope,
        VaultConfiguration configuration, ManagementReceipt receipt, bool recover, CancellationToken cancellationToken)
    {
        ArgumentNullException.ThrowIfNull(scope);
        ArgumentNullException.ThrowIfNull(configuration);
        return Mutate(scope, recover ? ManagementMutation.RecoverVault : ManagementMutation.CreateOrUpdateVault,
            receipt, scope.ResourceId, RequestMethod.Put, [200, 201], async (client, transport, token) =>
            {
                var collection = client.GetResourceGroupResource(new ResourceIdentifier(scope.ResourceGroup.ResourceId))
                    .GetKeyVaults();
                var operation = await collection.CreateOrUpdateAsync(WaitUntil.Started, scope.VaultName,
                    configuration.ToNative(recover), token).ConfigureAwait(false);
                bool Validate() => operation.HasValue && Same(operation.Value.Data.Id, scope.ResourceId);
                if (operation.HasValue && !Validate())
                {
                    throw new ControlledTransport.BoundaryException();
                }

                return ManagementOperation.From(operation, transport, _timeout, _time, Validate);
            }, cancellationToken);
    }

    public ValueTask<SecretOutcome<VaultObservation>> UpdateSettingsAsync(VaultScope scope,
        VaultSettingsPatch settings, ManagementReceipt receipt, CancellationToken cancellationToken = default)
    {
        ArgumentNullException.ThrowIfNull(scope);
        ArgumentNullException.ThrowIfNull(settings);
        return Mutate(scope, ManagementMutation.UpdateVault, receipt, scope.ResourceId, RequestMethod.Patch,
            [200, 201], async (client, _, token) => Observe(scope,
                (await client.GetKeyVaultResource(new ResourceIdentifier(scope.ResourceId))
                    .UpdateAsync(settings.ToNative(), token).ConfigureAwait(false)).Value.Data), cancellationToken);
    }

    public ValueTask<SecretOutcome<ManagementOperation>> DeleteVaultAsync(VaultScope scope,
        ManagementReceipt receipt, CancellationToken cancellationToken = default)
    {
        ArgumentNullException.ThrowIfNull(scope);
        return Mutate(scope, ManagementMutation.DeleteVault, receipt, scope.ResourceId, RequestMethod.Delete,
            [200, 204], async (client, transport, token) => ManagementOperation.From(
                await client.GetKeyVaultResource(new ResourceIdentifier(scope.ResourceId))
                    .DeleteAsync(WaitUntil.Started, token).ConfigureAwait(false), transport, _timeout, _time),
            cancellationToken);
    }

    public ValueTask<SecretOutcome<ManagementOperation>> PurgeDeletedVaultAsync(DeletedVaultScope scope,
        ManagementReceipt receipt, CancellationToken cancellationToken = default)
    {
        ArgumentNullException.ThrowIfNull(scope);
        return Mutate(scope, ManagementMutation.PurgeDeletedVault, receipt, scope.ResourceId + "/purge",
            RequestMethod.Post, [200, 202], async (client, transport, token) => ManagementOperation.From(
                await client.GetDeletedKeyVaultResource(new ResourceIdentifier(scope.ResourceId))
                    .PurgeDeletedAsync(WaitUntil.Started, token).ConfigureAwait(false),
                transport, _timeout, _time), cancellationToken);
    }

    public ValueTask<SecretOutcome<AccessPolicyObservation>> ChangeAccessPoliciesAsync(VaultScope scope,
        AccessPolicyChange change, IReadOnlyList<SecretAccessPolicy> policies, ManagementReceipt receipt,
        CancellationToken cancellationToken = default)
    {
        ArgumentNullException.ThrowIfNull(scope);
        ArgumentNullException.ThrowIfNull(policies);
        var selected = policies.ToArray();
        if (!Enum.IsDefined(change) || selected.Length is < 1 or > 16 || selected.Any(p => p is null) ||
            selected.Select(p => (p.TenantId, p.ObjectId, p.ApplicationId)).Distinct().Count() != selected.Length)
        {
            return ValueTask.FromResult(SecretOutcome<AccessPolicyObservation>.Failure(SecretStatus.Invalid));
        }

        var operation = change switch
        {
            AccessPolicyChange.Add => ManagementMutation.AddAccessPolicy,
            AccessPolicyChange.Replace => ManagementMutation.ReplaceAccessPolicy,
            _ => ManagementMutation.RemoveAccessPolicy
        };
        var kind = change switch
        {
            AccessPolicyChange.Add => AccessPolicyUpdateKind.Add,
            AccessPolicyChange.Replace => AccessPolicyUpdateKind.Replace,
            _ => AccessPolicyUpdateKind.Remove
        };
        return Mutate(scope, operation, receipt, $"{scope.ResourceId}/accessPolicies/{kind}", RequestMethod.Put,
            [200, 201], async (client, _, token) =>
            {
                var native = new KeyVaultAccessPolicyParameters(
                    new KeyVaultAccessPolicyProperties(selected.Select(p => p.ToNative())));
                var result = (await client.GetKeyVaultResource(new ResourceIdentifier(scope.ResourceId))
                    .UpdateAccessPolicyAsync(kind, native, token).ConfigureAwait(false)).Value;
                // This endpoint represents the parent vault, not an arbitrary policy resource.
                if (!Same(result.Id, scope.ResourceId))
                {
                    throw new ControlledTransport.BoundaryException();
                }

                var projected = result.AccessPolicies.Select(p =>
                {
                    if (!Guid.TryParse(p.ObjectId, out var principal) || p.Permissions is null)
                    {
                        throw new ControlledTransport.BoundaryException();
                    }

                    var permissions = p.Permissions.Secrets.Select(v =>
                        Enum.TryParse<SecretPermission>(v.ToString(), true, out var permission) && Enum.IsDefined(permission)
                            ? permission : throw new ControlledTransport.BoundaryException());
                    return new SecretAccessPolicy(p.TenantId, principal, permissions, p.ApplicationId);
                }).ToArray();
                return new AccessPolicyObservation(projected);
            }, cancellationToken);
    }

    private async ValueTask<SecretOutcome<T>> Mutate<T>(ManagementScope scope, ManagementMutation operation,
        ManagementReceipt receipt, string path, RequestMethod method, int[] statuses,
        Func<ArmClient, ControlledTransport, CancellationToken, Task<T>> dispatch,
        CancellationToken cancellationToken, string revision = Revision) where T : notnull
    {
        ArgumentNullException.ThrowIfNull(receipt);
        if (!ReferenceEquals(receipt.Authority, _authority) || !ReferenceEquals(receipt.Scope, scope) ||
            receipt.Operation != operation || Interlocked.Exchange(ref receipt.Used, 1) != 0)
        {
            return SecretOutcome<T>.Failure(SecretStatus.Invalid);
        }

        cancellationToken.ThrowIfCancellationRequested();
        using var deadline = new CancellationTokenSource(_timeout, _time);
        using var linked = CancellationTokenSource.CreateLinkedTokenSource(cancellationToken, deadline.Token);
        try
        {
            var client = Client(path, method, statuses, out var transport, receipt, revision);
            var value = await dispatch(client, transport, linked.Token).ConfigureAwait(false);
            if (receipt.Evidence != DispatchEvidence.PossiblyDispatched)
            {
                return SecretOutcome<T>.Failure(SecretStatus.Unknown);
            }

            if (value is VaultObservation
                {
                    ProvisioningState: NativeProvisioningState.Unknown or NativeProvisioningState.Failed or
                        NativeProvisioningState.Canceled
                })
            {
                return SecretOutcome<T>.Failure(SecretStatus.Unknown);
            }

            var evidence = value is ManagementOperation { State: NativeProvisioningState.Pending } ||
                value is VaultObservation { ProvisioningState: NativeProvisioningState.Pending }
                ? DispatchEvidence.Pending : DispatchEvidence.Applied;
            receipt.Receipt.Record(evidence);
            cancellationToken.ThrowIfCancellationRequested();
            return SecretOutcome<T>.Success(value);
        }
        catch (OperationCanceledException)
        {
            cancellationToken.ThrowIfCancellationRequested();
            return SecretOutcome<T>.Failure(receipt.Evidence == DispatchEvidence.PossiblyDispatched
                ? SecretStatus.Unknown : SecretStatus.Unavailable);
        }
        catch (Exception exception)
        {
            cancellationToken.ThrowIfCancellationRequested();
            if (receipt.Evidence == DispatchEvidence.PossiblyDispatched)
            {
                if (exception is RequestFailedException { Status: 400 or 401 or 403 or 404 or 409 or 429 })
                {
                    receipt.Receipt.Record(exception is RequestFailedException { Status: 409 }
                        ? DispatchEvidence.Conflict : DispatchEvidence.Rejected);
                }
                else
                {
                    return SecretOutcome<T>.Failure(SecretStatus.Unknown);
                }
            }

            return SecretOutcome<T>.Failure(ControlledTransport.Failure(exception));
        }
    }

    public ValueTask<ManagementInventory<VaultObservation>> ListVaultsAsync(ResourceGroupScope scope,
        CollectionLimits limits, CancellationToken cancellationToken = default)
    {
        ArgumentNullException.ThrowIfNull(scope);
        return Collect($"{scope.ResourceId}/providers/Microsoft.KeyVault/vaults", limits,
            (client, token) => client.GetResourceGroupResource(new ResourceIdentifier(scope.ResourceId))
                .GetKeyVaults().GetAllAsync(cancellationToken: token),
            resource => Observe(ParseVault(resource.Id.ToString(), scope.Subscription, scope), resource.Data),
            cancellationToken);
    }

    public ValueTask<ManagementInventory<VaultObservation>> ListVaultsAsync(SubscriptionScope scope,
        CollectionLimits limits, CancellationToken cancellationToken = default)
    {
        ArgumentNullException.ThrowIfNull(scope);
        return Collect($"{scope.ResourceId}/providers/Microsoft.KeyVault/vaults", limits,
            (client, token) => client.GetSubscriptionResource(new ResourceIdentifier(scope.ResourceId))
                .GetKeyVaultsAsync(cancellationToken: token),
            resource => Observe(ParseVault(resource.Id.ToString(), scope), resource.Data), cancellationToken);
    }

    public ValueTask<ManagementInventory<DeletedVaultObservation>> ListDeletedVaultsAsync(SubscriptionScope scope,
        CollectionLimits limits, CancellationToken cancellationToken = default)
    {
        ArgumentNullException.ThrowIfNull(scope);
        return Collect($"{scope.ResourceId}/providers/Microsoft.KeyVault/deletedVaults", limits,
            (client, token) => client.GetSubscriptionResource(new ResourceIdentifier(scope.ResourceId))
                .GetDeletedKeyVaultsAsync(token),
            resource =>
            {
                var parts = resource.Id.ToString().Split('/');
                if (parts.Length != 9 || !parts[1].Equals("subscriptions", StringComparison.OrdinalIgnoreCase) ||
                    !parts[2].Equals(scope.SubscriptionId.ToString("D"), StringComparison.OrdinalIgnoreCase) ||
                    !parts[3].Equals("providers", StringComparison.OrdinalIgnoreCase) ||
                    !parts[4].Equals("Microsoft.KeyVault", StringComparison.OrdinalIgnoreCase) ||
                    !parts[5].Equals("locations", StringComparison.OrdinalIgnoreCase) ||
                    !parts[7].Equals("deletedVaults", StringComparison.OrdinalIgnoreCase))
                {
                    throw new ControlledTransport.BoundaryException();
                }

                return ObserveDeleted(new DeletedVaultScope(scope, parts[6], parts[8]), resource.Data);
            }, cancellationToken);
    }

    public ValueTask<SecretOutcome<PrivateConnectionObservation>> GetPrivateConnectionAsync(PrivateConnectionScope scope,
        CancellationToken cancellationToken = default)
    {
        ArgumentNullException.ThrowIfNull(scope);
        return Read(scope.ResourceId, async (client, token) => ObserveConnection(scope,
            (await client.GetKeyVaultPrivateEndpointConnectionResource(new ResourceIdentifier(scope.ResourceId))
                .GetAsync(token).ConfigureAwait(false)).Value.Data), cancellationToken, [200, 204]);
    }

    public ValueTask<ManagementInventory<PrivateConnectionObservation>> ListPrivateConnectionsAsync(VaultScope scope,
        CollectionLimits limits, CancellationToken cancellationToken = default)
    {
        ArgumentNullException.ThrowIfNull(scope);
        return Collect($"{scope.ResourceId}/privateEndpointConnections", limits,
            (client, token) => client.GetKeyVaultResource(new ResourceIdentifier(scope.ResourceId))
                .GetKeyVaultPrivateEndpointConnections().GetAllAsync(token),
            resource => ObserveConnection(new PrivateConnectionScope(scope, resource.Id.Name), resource.Data),
            cancellationToken);
    }

    public ValueTask<ManagementInventory<PrivateLinkObservation>> ListPrivateLinkResourcesAsync(VaultScope scope,
        CollectionLimits limits, CancellationToken cancellationToken = default)
    {
        ArgumentNullException.ThrowIfNull(scope);
        return Collect($"{scope.ResourceId}/privateLinkResources", limits,
            (client, token) => client.GetKeyVaultResource(new ResourceIdentifier(scope.ResourceId))
                .GetPrivateLinkResourcesAsync(token),
            resource =>
            {
                if (!Same(resource.Id, $"{scope.ResourceId}/privateLinkResources/{resource.Name}"))
                {
                    throw new ControlledTransport.BoundaryException();
                }

                return new PrivateLinkObservation(resource.Name, resource.GroupId,
                    resource.RequiredMembers, resource.RequiredZoneNames);
            }, cancellationToken);
    }

    /// <summary>Approves or rejects an existing connection. Does not provision a private endpoint.</summary>
    public ValueTask<SecretOutcome<ManagementOperation>> UpdatePrivateConnectionAsync(PrivateConnectionScope scope,
        PrivateConnectionState state, ManagementReceipt receipt, CancellationToken cancellationToken = default)
    {
        ArgumentNullException.ThrowIfNull(scope);
        if (state is not (PrivateConnectionState.Approved or PrivateConnectionState.Rejected))
        {
            return ValueTask.FromResult(SecretOutcome<ManagementOperation>.Failure(SecretStatus.Invalid));
        }

        return Mutate(scope, ManagementMutation.UpdatePrivateConnection, receipt, scope.ResourceId, RequestMethod.Put,
            [200], async (client, transport, token) =>
            {
                var data = new KeyVaultPrivateEndpointConnectionData
                {
                    ConnectionState = new KeyVaultPrivateLinkServiceConnectionState
                    {
                        Status = new KeyVaultPrivateEndpointServiceConnectionStatus(state.ToString())
                    }
                };
                var operation = await client.GetKeyVaultPrivateEndpointConnectionResource(
                    new ResourceIdentifier(scope.ResourceId)).UpdateAsync(WaitUntil.Started, data, token)
                    .ConfigureAwait(false);
                bool Validate() => operation.HasValue && Same(operation.Value.Id, scope.ResourceId);
                if (operation.HasValue && !Validate())
                {
                    throw new ControlledTransport.BoundaryException();
                }

                return ManagementOperation.From(operation, transport, _timeout, _time, Validate);
            }, cancellationToken);
    }

    public ValueTask<SecretOutcome<ManagementOperation>> DeletePrivateConnectionAsync(PrivateConnectionScope scope,
        ManagementReceipt receipt, CancellationToken cancellationToken = default)
    {
        ArgumentNullException.ThrowIfNull(scope);
        return Mutate(scope, ManagementMutation.DeletePrivateConnection, receipt, scope.ResourceId, RequestMethod.Delete,
            [200, 202, 204], async (client, transport, token) => ManagementOperation.From(
                await client.GetKeyVaultPrivateEndpointConnectionResource(new ResourceIdentifier(scope.ResourceId))
                    .DeleteAsync(WaitUntil.Started, token).ConfigureAwait(false), transport, _timeout, _time),
            cancellationToken);
    }

    private async ValueTask<ManagementInventory<T>> Collect<TResource, T>(string path, CollectionLimits limits,
        Func<ArmClient, CancellationToken, AsyncPageable<TResource>> getPages, Func<TResource, T> project,
        CancellationToken cancellationToken, string revision = Revision, RequestMethod? method = null)
        where TResource : notnull where T : notnull
    {
        ArgumentNullException.ThrowIfNull(limits);
        using var deadline = new CancellationTokenSource(limits.Timeout, _time);
        using var linked = CancellationTokenSource.CreateLinkedTokenSource(cancellationToken, deadline.Token);
        var items = new List<T>();
        int pages = 0;
        var client = Client(path, method ?? RequestMethod.Get, [200], out var transport, revision: revision);
        try
        {
            await foreach (var page in getPages(client, linked.Token)
                .AsPages(pageSizeHint: Math.Min(100, limits.MaximumItems)).ConfigureAwait(false))
            {
                pages++;
                int remaining = limits.MaximumItems - items.Count;
                // Validate even overflow rows before publishing a partial page.
                foreach (var resource in page.Values)
                {
                    linked.Token.ThrowIfCancellationRequested();
                    var value = project(resource);
                    if (items.Count < limits.MaximumItems)
                    {
                        items.Add(value);
                    }
                    else if (value is NotificationDeliveryAttribute attribute)
                    {
                        attribute.Dispose();
                    }
                }

                bool complete = page.ContinuationToken is null && !transport.HasContinuation &&
                    page.Values.Count <= remaining;
                if (page.ContinuationToken is null && transport.HasContinuation)
                {
                    return new(items, false, SecretStatus.Unsupported);
                }

                if (complete || pages >= limits.MaximumPages || items.Count >= limits.MaximumItems)
                {
                    return new(items, complete, SecretStatus.Success);
                }
            }

            return transport.HasContinuation ? new(items, false, SecretStatus.Unsupported) :
                new(items, true, SecretStatus.Success);
        }
        catch (OperationCanceledException)
        {
            if (cancellationToken.IsCancellationRequested)
            {
                foreach (var attribute in items.OfType<NotificationDeliveryAttribute>()) attribute.Dispose();
            }
            cancellationToken.ThrowIfCancellationRequested();
            return new(items, false, SecretStatus.Unavailable);
        }
        catch (Exception exception)
        {
            if (cancellationToken.IsCancellationRequested)
            {
                foreach (var attribute in items.OfType<NotificationDeliveryAttribute>()) attribute.Dispose();
            }
            cancellationToken.ThrowIfCancellationRequested();
            return new(items, false, ControlledTransport.Failure(exception));
        }
    }

    private static bool Same(ResourceIdentifier? actual, string expected) =>
        actual is not null && actual.ToString().Equals(expected, StringComparison.OrdinalIgnoreCase);

    private static VaultScope ParseVault(string id, SubscriptionScope subscription, ResourceGroupScope? group = null)
    {
        var parts = id.Split('/');
        if (parts.Length != 9 || !parts[1].Equals("subscriptions", StringComparison.OrdinalIgnoreCase) ||
            !parts[2].Equals(subscription.SubscriptionId.ToString("D"), StringComparison.OrdinalIgnoreCase) ||
            !parts[3].Equals("resourceGroups", StringComparison.OrdinalIgnoreCase) ||
            !parts[5].Equals("providers", StringComparison.OrdinalIgnoreCase) ||
            !parts[6].Equals("Microsoft.KeyVault", StringComparison.OrdinalIgnoreCase) ||
            !parts[7].Equals("vaults", StringComparison.OrdinalIgnoreCase) ||
            (group is not null && !parts[4].Equals(group.ResourceGroup, StringComparison.OrdinalIgnoreCase)))
        {
            throw new ControlledTransport.BoundaryException();
        }

        return new VaultScope(group ?? new ResourceGroupScope(subscription, parts[4]), parts[8]);
    }

    private static VaultObservation Observe(VaultScope scope, KeyVaultData data)
    {
        if (!Same(data.Id, scope.ResourceId))
        {
            throw new ControlledTransport.BoundaryException();
        }

        return new(scope, Provisioning(data.Properties.ProvisioningState?.ToString()),
            data.Properties.EnableRbacAuthorization, data.Properties.EnablePurgeProtection,
            data.Properties.SoftDeleteRetentionInDays);
    }

    private static DeletedVaultObservation ObserveDeleted(DeletedVaultScope scope, DeletedKeyVaultData data)
    {
        if (!Same(data.Id, scope.ResourceId))
        {
            throw new ControlledTransport.BoundaryException();
        }

        return new(scope, data.Properties.DeletedOn, data.Properties.ScheduledPurgeOn,
            data.Properties.PurgeProtectionEnabled);
    }

    private static PrivateConnectionObservation ObserveConnection(PrivateConnectionScope scope,
        KeyVaultPrivateEndpointConnectionData data)
    {
        if (!Same(data.Id, scope.ResourceId))
        {
            throw new ControlledTransport.BoundaryException();
        }

        var value = data.ConnectionState?.Status?.ToString();
        var state = Enum.TryParse<PrivateConnectionState>(value, true, out var parsed) && Enum.IsDefined(parsed)
            ? parsed : PrivateConnectionState.Unknown;
        return new(scope, state, Provisioning(data.ProvisioningState?.ToString()));
    }

    private static NativeProvisioningState Provisioning(string? value) => value?.ToLowerInvariant() switch
    {
        "succeeded" => NativeProvisioningState.Succeeded,
        "failed" => NativeProvisioningState.Failed,
        "canceled" or "cancelled" => NativeProvisioningState.Canceled,
        "creating" or "updating" or "deleting" or "accepted" or "running" or "inprogress" =>
            NativeProvisioningState.Pending,
        _ => NativeProvisioningState.Unknown
    };
}
