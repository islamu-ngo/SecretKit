using Azure;
using Azure.Core;
using Azure.Core.Pipeline;
using Azure.ResourceManager;
using Azure.ResourceManager.KeyVault;
using Azure.ResourceManager.KeyVault.Models;
using Azure.ResourceManager.Resources;
using SecretKit.Core;
using SecretKit.Internal;

namespace SecretKit.AzureKeyVault.Management;

/// <summary>
/// Azure public cloud only, Key Vault ARM 2026-02-01. Explicit administration identity,
/// host-owned transport, no data-plane access and no runtime delivery proof.
/// </summary>
public sealed partial class VaultAdministration
{
    private static readonly ArmEnvironment Cloud = ArmEnvironment.AzurePublicCloud;
    private readonly ArmClient _client;
    private readonly HttpPipelineTransport _transport;
    private readonly int _maximumBytes;
    private readonly TimeSpan _timeout;
    private readonly TimeProvider _time;
    private readonly SecretAuthority _authority = new();

    /// <summary>Borrows an explicit administrative identity and transport without token acquisition or provider calls.</summary>
    /// <param name="administrativeCredential">Host-owned administrative credential; never used implicitly for runtime reads.</param>
    /// <param name="transport">Host-owned transport; its instrumentation and internal retries remain host responsibility.</param>
    /// <param name="maximumResponseBytes">The local response bound, from 1 KiB through 16 MiB.</param>
    /// <param name="timeout">A positive cooperative operation budget up to two minutes; null selects 30 seconds.</param>
    /// <param name="timeProvider">The deadline clock, or the system clock.</param>
    /// <exception cref="ArgumentNullException">The credential or transport is null.</exception>
    /// <exception cref="ArgumentOutOfRangeException">A byte or time budget is invalid.</exception>
    public VaultAdministration(TokenCredential administrativeCredential, HttpPipelineTransport transport,
        int maximumResponseBytes = 1024 * 1024, TimeSpan? timeout = null, TimeProvider? timeProvider = null)
    {
        ArgumentNullException.ThrowIfNull(administrativeCredential);
        ArgumentNullException.ThrowIfNull(transport);
        if (!TransferLimits.IsValidByteBudget(maximumResponseBytes))
        {
            throw new ArgumentOutOfRangeException(nameof(maximumResponseBytes));
        }

        _transport = transport;
        _maximumBytes = maximumResponseBytes;
        _timeout = timeout ?? TimeSpan.FromSeconds(30);
        if (_timeout <= TimeSpan.Zero || _timeout > TimeSpan.FromMinutes(2))
        {
            throw new ArgumentOutOfRangeException(nameof(timeout));
        }

        _time = timeProvider ?? TimeProvider.System;
        _client = CreateClient(administrativeCredential, transport);
    }

    /// <summary>Creates read-only evidence bound to this client, exact scope instance and selected native mutation.</summary>
    /// <param name="scope">The native scope instance that will also be passed to the mutation.</param>
    /// <param name="operation">The mutation whose scope kind must match.</param>
    /// <returns>Unused local evidence; creation grants no permission and performs no provider call.</returns>
    /// <exception cref="ArgumentNullException">The scope is null.</exception>
    /// <exception cref="ArgumentException">The scope kind and mutation do not match.</exception>
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

    private ControlledTransport Route(ArmCallTarget target, RequestMethod method, int[] statuses,
        ManagementReceipt? receipt = null) =>
        new(_transport, Cloud.Endpoint, target.Path, method, target.Contract.ApiVersion, statuses, _maximumBytes, receipt);

    private static ArmClient CreateClient(TokenCredential credential, HttpPipelineTransport transport)
    {
        var options = new ArmClientOptions
        {
            Environment = Cloud,
            Transport = new AzureCallPipeline(transport)
        };
        options.Diagnostics.IsLoggingEnabled = false;
        options.Diagnostics.IsLoggingContentEnabled = false;
        options.Diagnostics.IsDistributedTracingEnabled = false;
        options.Retry.MaxRetries = 0;
        options.AddPolicy(new AzureCallPipeline.CapturePolicy(), HttpPipelinePosition.PerCall);
        return new ArmClient(credential, null, options);
    }

    private async ValueTask<SecretOutcome<T>> Read<T>(ArmCallTarget target, Func<ArmClient, CancellationToken, Task<T>> read,
        CancellationToken cancellationToken, int[]? statuses = null,
        RequestMethod? method = null) where T : notnull
    {
        using var observation = new AzureManagementDiagnostics.Observation(AzureDiagnosticOperation.AdministrativeRead, _time, cancellationToken);
        using var deadline = new CancellationTokenSource(_timeout, _time);
        using var linked = CancellationTokenSource.CreateLinkedTokenSource(cancellationToken, deadline.Token);
        cancellationToken.ThrowIfCancellationRequested();
        var transport = Route(target, method ?? RequestMethod.Get, statuses ?? [200]);
        T? value = default;
        try
        {
            using (AzureCallPipeline.Bind(transport))
                value = await read(_client, linked.Token).ConfigureAwait(false);
            cancellationToken.ThrowIfCancellationRequested();
            if (transport.LastStatus == 204)
            {
                return observation.Record(SecretOutcome<T>.Failure(SecretStatus.Absent));
            }

            return observation.Record(SecretOutcome<T>.Success(value));
        }
        catch (OperationCanceledException)
        {
            observation.Cancel(deadline.IsCancellationRequested);
            if (value is NotificationFullUrl fullUrl) fullUrl.Dispose();
            cancellationToken.ThrowIfCancellationRequested();
            return observation.Record(SecretOutcome<T>.Failure(SecretStatus.Unavailable));
        }
        catch (Exception exception)
        {
            if (deadline.IsCancellationRequested) observation.Cancel(true);
            cancellationToken.ThrowIfCancellationRequested();
            if (transport.LastStatus == 204)
            {
                return observation.Record(SecretOutcome<T>.Failure(SecretStatus.Absent));
            }

            return observation.Record(SecretOutcome<T>.Failure(ControlledTransport.Failure(exception)));
        }
    }

    /// <summary>Reads selected vault control-plane metadata without acquiring secret values.</summary>
    /// <param name="scope">The exact vault coordinates.</param>
    /// <param name="cancellationToken">Cancels the read and propagates caller cancellation.</param>
    /// <returns>Validated metadata, not runtime delivery evidence, or a bounded failure.</returns>
    /// <exception cref="ArgumentNullException">The scope is null.</exception>
    /// <exception cref="OperationCanceledException">Caller cancellation was observed.</exception>
    public ValueTask<SecretOutcome<VaultObservation>> GetVaultAsync(VaultScope scope,
        CancellationToken cancellationToken = default)
    {
        ArgumentNullException.ThrowIfNull(scope);
        return Read(ArmCallTarget.At(ArmMethodContracts.VaultGet, scope), async (client, token) => Observe(scope,
            (await client.GetKeyVaultResource(new ResourceIdentifier(scope.ResourceId)).GetAsync(token)
                .ConfigureAwait(false)).Value.Data), cancellationToken);
    }

    /// <summary>Reads native deleted-vault metadata without recovering or purging the vault.</summary>
    /// <param name="scope">The exact deleted-vault location and coordinates.</param>
    /// <param name="cancellationToken">Cancels the read and propagates caller cancellation.</param>
    /// <returns>Validated deletion/protection metadata, or a bounded failure.</returns>
    /// <exception cref="ArgumentNullException">The scope is null.</exception>
    /// <exception cref="OperationCanceledException">Caller cancellation was observed.</exception>
    public ValueTask<SecretOutcome<DeletedVaultObservation>> GetDeletedVaultAsync(DeletedVaultScope scope,
        CancellationToken cancellationToken = default)
    {
        ArgumentNullException.ThrowIfNull(scope);
        return Read(ArmCallTarget.At(ArmMethodContracts.VaultGetDeleted, scope), async (client, token) => ObserveDeleted(scope,
            (await client.GetDeletedKeyVaultResource(new ResourceIdentifier(scope.ResourceId)).GetAsync(token)
                .ConfigureAwait(false)).Value.Data), cancellationToken);
    }

    /// <summary>Observes native vault-name availability without reserving or creating a vault.</summary>
    /// <param name="subscription">The explicitly selected subscription.</param>
    /// <param name="vaultName">The validated native name to check.</param>
    /// <param name="cancellationToken">Cancels the check and propagates caller cancellation.</param>
    /// <returns>A nullable availability observation, or a bounded failure; availability may immediately change.</returns>
    /// <exception cref="ArgumentNullException">The subscription is null.</exception>
    /// <exception cref="ArgumentException">The vault name is invalid.</exception>
    /// <exception cref="OperationCanceledException">Caller cancellation was observed.</exception>
    public async ValueTask<SecretOutcome<VaultNameAvailability>> CheckNameAvailabilityAsync(
        SubscriptionScope subscription, string vaultName, CancellationToken cancellationToken = default)
    {
        using var observation = new AzureManagementDiagnostics.Observation(AzureDiagnosticOperation.NameAvailability, _time, cancellationToken);
        ArgumentNullException.ThrowIfNull(subscription);
        VaultScope.ValidateName(vaultName);
        using var deadline = new CancellationTokenSource(_timeout, _time);
        using var linked = CancellationTokenSource.CreateLinkedTokenSource(cancellationToken, deadline.Token);
        cancellationToken.ThrowIfCancellationRequested();
        try
        {
            using var call = AzureCallPipeline.Bind(Route(ArmCallTarget.Below(ArmMethodContracts.VaultCheckNameAvailability, subscription),
                RequestMethod.Post, [200]));
            var response = await _client.GetSubscriptionResource(new ResourceIdentifier(subscription.ResourceId))
                .CheckKeyVaultNameAvailabilityAsync(new KeyVaultNameAvailabilityContent(vaultName), linked.Token)
                .ConfigureAwait(false);
            return observation.Record(SecretOutcome<VaultNameAvailability>.Success(new(response.Value.NameAvailable)));
        }
        catch (OperationCanceledException)
        {
            observation.Cancel(deadline.IsCancellationRequested);
            cancellationToken.ThrowIfCancellationRequested();
            return observation.Record(SecretOutcome<VaultNameAvailability>.Failure(SecretStatus.Unavailable));
        }
        catch (Exception exception)
        {
            if (deadline.IsCancellationRequested) observation.Cancel(true);
            cancellationToken.ThrowIfCancellationRequested();
            return observation.Record(SecretOutcome<VaultNameAvailability>.Failure(ControlledTransport.Failure(exception)));
        }
    }

    /// <summary>Explicit create/update, not conditional create. Recover uses native createMode, not empty creation.</summary>
    /// <param name="scope">The vault to create or replace.</param>
    /// <param name="configuration">The complete supported configuration selection.</param>
    /// <param name="receipt">Unused evidence prepared by this client for this scope and CreateOrUpdateVault.</param>
    /// <param name="cancellationToken">Cancels locally without undoing a dispatched effect.</param>
    /// <returns>An operation handle for explicit status checks, or a bounded failure; no automatic replay occurs.</returns>
    /// <exception cref="ArgumentNullException">The scope, configuration or receipt is null.</exception>
    /// <exception cref="OperationCanceledException">Caller cancellation was observed; inspect retained receipt evidence.</exception>
    public ValueTask<SecretOutcome<ManagementOperation>> CreateOrUpdateVaultAsync(VaultScope scope,
        VaultConfiguration configuration, ManagementReceipt receipt, CancellationToken cancellationToken = default) =>
        CreateVault(scope, configuration, receipt, false, cancellationToken);

    /// <summary>Requests native vault recovery using the recovery create mode; it does not create an empty replacement.</summary>
    /// <param name="scope">The intended recovered vault coordinates.</param>
    /// <param name="configuration">The explicit supported native recovery configuration.</param>
    /// <param name="receipt">Unused client-prepared evidence for this scope and RecoverVault.</param>
    /// <param name="cancellationToken">Cancels locally without undoing recovery.</param>
    /// <returns>An operation handle for explicit status checks, or a bounded failure.</returns>
    /// <exception cref="ArgumentNullException">The scope, configuration or receipt is null.</exception>
    /// <exception cref="OperationCanceledException">Caller cancellation was observed; inspect retained receipt evidence.</exception>
    public ValueTask<SecretOutcome<ManagementOperation>> RecoverVaultAsync(VaultScope scope,
        VaultConfiguration configuration, ManagementReceipt receipt, CancellationToken cancellationToken = default) =>
        CreateVault(scope, configuration, receipt, true, cancellationToken);

    private ValueTask<SecretOutcome<ManagementOperation>> CreateVault(VaultScope scope,
        VaultConfiguration configuration, ManagementReceipt receipt, bool recover, CancellationToken cancellationToken)
    {
        ArgumentNullException.ThrowIfNull(scope);
        ArgumentNullException.ThrowIfNull(configuration);
        return Mutate(scope, recover ? ManagementMutation.RecoverVault : ManagementMutation.CreateOrUpdateVault,
            receipt, ArmCallTarget.At(ArmMethodContracts.VaultCreateOrUpdate, scope), RequestMethod.Put, [200, 201], async (client, transport, token) =>
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

    /// <summary>Patches selected vault settings; omitted fields are not reset and purge protection cannot be disabled.</summary>
    /// <param name="scope">The exact vault to update.</param>
    /// <param name="settings">The supported nonempty settings patch.</param>
    /// <param name="receipt">Unused client-prepared evidence for this scope and UpdateVault.</param>
    /// <param name="cancellationToken">Cancels locally; a dispatched update may already be applied.</param>
    /// <returns>Validated native metadata, or a bounded failure without replay.</returns>
    /// <exception cref="ArgumentNullException">The scope, settings or receipt is null.</exception>
    /// <exception cref="OperationCanceledException">Caller cancellation was observed; inspect retained receipt evidence.</exception>
    public ValueTask<SecretOutcome<VaultObservation>> UpdateSettingsAsync(VaultScope scope,
        VaultSettingsPatch settings, ManagementReceipt receipt, CancellationToken cancellationToken = default)
    {
        ArgumentNullException.ThrowIfNull(scope);
        ArgumentNullException.ThrowIfNull(settings);
        return Mutate(scope, ManagementMutation.UpdateVault, receipt, ArmCallTarget.At(ArmMethodContracts.VaultUpdate, scope), RequestMethod.Patch,
            [200, 201], async (client, _, token) => Observe(scope,
                (await client.GetKeyVaultResource(new ResourceIdentifier(scope.ResourceId))
                    .UpdateAsync(settings.ToNative(), token).ConfigureAwait(false)).Value.Data), cancellationToken);
    }

    /// <summary>Requests vault deletion subject to native retention policy; no background wait or replay is performed.</summary>
    /// <param name="scope">The exact vault to delete.</param>
    /// <param name="receipt">Unused client-prepared evidence for this scope and DeleteVault.</param>
    /// <param name="cancellationToken">Cancels locally without proving deletion did not occur.</param>
    /// <returns>A local operation handle, or a bounded failure.</returns>
    /// <exception cref="ArgumentNullException">The scope or receipt is null.</exception>
    /// <exception cref="OperationCanceledException">Caller cancellation was observed; inspect retained receipt evidence.</exception>
    public ValueTask<SecretOutcome<ManagementOperation>> DeleteVaultAsync(VaultScope scope,
        ManagementReceipt receipt, CancellationToken cancellationToken = default)
    {
        ArgumentNullException.ThrowIfNull(scope);
        return Mutate(scope, ManagementMutation.DeleteVault, receipt, ArmCallTarget.At(ArmMethodContracts.VaultDelete, scope), RequestMethod.Delete,
            [200, 204], async (client, transport, token) => ManagementOperation.From(
                await client.GetKeyVaultResource(new ResourceIdentifier(scope.ResourceId))
                    .DeleteAsync(WaitUntil.Started, token).ConfigureAwait(false), transport, _timeout, _time),
            cancellationToken);
    }

    /// <summary>Requests permanent removal of a deleted vault; native protection and permissions remain authoritative.</summary>
    /// <param name="scope">The exact deleted-vault coordinates.</param>
    /// <param name="receipt">Unused client-prepared evidence for this scope and PurgeDeletedVault.</param>
    /// <param name="cancellationToken">Cancels locally without undoing an applied purge.</param>
    /// <returns>A local operation handle, not proof of immediate global disappearance, or a bounded failure.</returns>
    /// <exception cref="ArgumentNullException">The scope or receipt is null.</exception>
    /// <exception cref="OperationCanceledException">Caller cancellation was observed; inspect retained receipt evidence.</exception>
    public ValueTask<SecretOutcome<ManagementOperation>> PurgeDeletedVaultAsync(DeletedVaultScope scope,
        ManagementReceipt receipt, CancellationToken cancellationToken = default)
    {
        ArgumentNullException.ThrowIfNull(scope);
        return Mutate(scope, ManagementMutation.PurgeDeletedVault, receipt, ArmCallTarget.Below(ArmMethodContracts.VaultPurgeDeleted, scope),
            RequestMethod.Post, [200, 202], async (client, transport, token) => ManagementOperation.From(
                await client.GetDeletedKeyVaultResource(new ResourceIdentifier(scope.ResourceId))
                    .PurgeDeletedAsync(WaitUntil.Started, token).ConfigureAwait(false),
                transport, _timeout, _time), cancellationToken);
    }

    /// <summary>Applies an explicit native secret-only policy change without proving effective runtime permissions.</summary>
    /// <param name="scope">The exact vault whose access policies are changed.</param>
    /// <param name="change">The native add, replace or remove operation.</param>
    /// <param name="policies">One to sixteen distinct policy entries copied before dispatch.</param>
    /// <param name="receipt">Unused client-prepared evidence for this scope and the matching policy mutation.</param>
    /// <param name="cancellationToken">Cancels locally without undoing a dispatched policy change.</param>
    /// <returns>Validated policy metadata, or a bounded failure without replay.</returns>
    /// <exception cref="ArgumentNullException">The scope, policies or receipt is null.</exception>
    /// <exception cref="OperationCanceledException">Caller cancellation was observed; inspect retained receipt evidence.</exception>
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
        return Mutate(scope, operation, receipt, ArmCallTarget.Below(ArmMethodContracts.AccessPolicyUpdate, scope, kind.ToString()), RequestMethod.Put,
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
        ManagementReceipt receipt, ArmCallTarget target, RequestMethod method, int[] statuses,
        Func<ArmClient, ControlledTransport, CancellationToken, Task<T>> dispatch,
        CancellationToken cancellationToken) where T : notnull
    {
        using var observation = new AzureManagementDiagnostics.Observation(AzureDiagnosticOperation.AdministrativeMutation, _time, cancellationToken, receipt);
        ArgumentNullException.ThrowIfNull(receipt);
        if (!ReferenceEquals(receipt.Authority, _authority) || !ReferenceEquals(receipt.Scope, scope) ||
            receipt.Operation != operation || Interlocked.Exchange(ref receipt.Used, 1) != 0)
        {
            return observation.Record(SecretOutcome<T>.Failure(SecretStatus.Invalid));
        }

        cancellationToken.ThrowIfCancellationRequested();
        using var deadline = new CancellationTokenSource(_timeout, _time);
        using var linked = CancellationTokenSource.CreateLinkedTokenSource(cancellationToken, deadline.Token);
        ControlledTransport? transport = null;
        try
        {
            transport = Route(target, method, statuses, receipt);
            T value;
            using (AzureCallPipeline.Bind(transport))
                value = await dispatch(_client, transport, linked.Token).ConfigureAwait(false);
            if (receipt.Evidence != DispatchEvidence.PossiblyDispatched)
            {
                return observation.Record(SecretOutcome<T>.Failure(SecretStatus.Unknown));
            }

            if (value is VaultObservation
                {
                    ProvisioningState: NativeProvisioningState.Unknown or NativeProvisioningState.Failed or
                        NativeProvisioningState.Canceled
                })
            {
                return observation.Record(SecretOutcome<T>.Failure(SecretStatus.Unknown));
            }

            var evidence = value is ManagementOperation { State: NativeProvisioningState.Pending } ||
                value is VaultObservation { ProvisioningState: NativeProvisioningState.Pending }
                ? DispatchEvidence.Pending : DispatchEvidence.Applied;
            receipt.Record(evidence);
            cancellationToken.ThrowIfCancellationRequested();
            return observation.Record(SecretOutcome<T>.Success(value));
        }
        catch (OperationCanceledException)
        {
            observation.Cancel(deadline.IsCancellationRequested);
            cancellationToken.ThrowIfCancellationRequested();
            return observation.Record(SecretOutcome<T>.Failure(receipt.Evidence == DispatchEvidence.PossiblyDispatched
                ? SecretStatus.Unknown : SecretStatus.Unavailable));
        }
        catch (Exception exception)
        {
            if (deadline.IsCancellationRequested) observation.Cancel(true);
            cancellationToken.ThrowIfCancellationRequested();
            if (receipt.Evidence == DispatchEvidence.PossiblyDispatched)
            {
                return observation.Record(SecretOutcome<T>.Failure(SecretStatus.Unknown));
            }

            return observation.Record(SecretOutcome<T>.Failure(
                transport?.DefinitiveMutationStatus is { } observed
                    ? SecretKit.AzureKeyVault.AzureFailureClassification.Status(observed)
                    : ControlledTransport.Failure(exception)));
        }
    }

    /// <summary>Collects bounded vault metadata in one resource group, without testing secret access.</summary>
    /// <param name="scope">The selected resource group.</param>
    /// <param name="limits">The local page/item/time budgets.</param>
    /// <param name="cancellationToken">Cancels enumeration and propagates caller cancellation.</param>
    /// <returns>Validated observations with explicit completeness and bounded failure status.</returns>
    /// <exception cref="ArgumentNullException">The scope or limits is null.</exception>
    /// <exception cref="OperationCanceledException">Caller cancellation was observed.</exception>
    public ValueTask<ManagementInventory<VaultObservation>> ListVaultsAsync(ResourceGroupScope scope,
        CollectionLimits limits, CancellationToken cancellationToken = default)
    {
        ArgumentNullException.ThrowIfNull(scope);
        return Collect(ArmCallTarget.Below(ArmMethodContracts.VaultListByResourceGroup, scope), limits,
            (client, token) => client.GetResourceGroupResource(new ResourceIdentifier(scope.ResourceId))
                .GetKeyVaults().GetAllAsync(cancellationToken: token),
            resource => Observe(ParseVault(resource.Id, scope.Subscription, scope), resource.Data),
            cancellationToken);
    }

    /// <summary>Collects bounded vault metadata across one subscription, without a remote snapshot.</summary>
    /// <param name="scope">The selected subscription.</param>
    /// <param name="limits">The local page/item/time budgets.</param>
    /// <param name="cancellationToken">Cancels enumeration and propagates caller cancellation.</param>
    /// <returns>Validated observations with explicit completeness and bounded failure status.</returns>
    /// <exception cref="ArgumentNullException">The scope or limits is null.</exception>
    /// <exception cref="OperationCanceledException">Caller cancellation was observed.</exception>
    public ValueTask<ManagementInventory<VaultObservation>> ListVaultsAsync(SubscriptionScope scope,
        CollectionLimits limits, CancellationToken cancellationToken = default)
    {
        ArgumentNullException.ThrowIfNull(scope);
        return Collect(ArmCallTarget.Below(ArmMethodContracts.VaultListBySubscription, scope), limits,
            (client, token) => client.GetSubscriptionResource(new ResourceIdentifier(scope.ResourceId))
                .GetKeyVaultsAsync(cancellationToken: token),
            resource => Observe(ParseVault(resource.Id, scope), resource.Data), cancellationToken);
    }

    /// <summary>Collects bounded deleted-vault metadata in one subscription without recovery or purge.</summary>
    /// <param name="scope">The selected subscription.</param>
    /// <param name="limits">The local page/item/time budgets.</param>
    /// <param name="cancellationToken">Cancels enumeration and propagates caller cancellation.</param>
    /// <returns>Validated deleted-vault observations with explicit completeness.</returns>
    /// <exception cref="ArgumentNullException">The scope or limits is null.</exception>
    /// <exception cref="OperationCanceledException">Caller cancellation was observed.</exception>
    public ValueTask<ManagementInventory<DeletedVaultObservation>> ListDeletedVaultsAsync(SubscriptionScope scope,
        CollectionLimits limits, CancellationToken cancellationToken = default)
    {
        ArgumentNullException.ThrowIfNull(scope);
        return Collect(ArmCallTarget.Below(ArmMethodContracts.VaultListDeleted, scope), limits,
            (client, token) => client.GetSubscriptionResource(new ResourceIdentifier(scope.ResourceId))
                .GetDeletedKeyVaultsAsync(token),
            resource =>
            {
                var id = resource.Id;
                if (id.ResourceType != DeletedKeyVaultResource.ResourceType ||
                    id.Location is not { } location)
                {
                    throw new ControlledTransport.BoundaryException();
                }

                var candidate = new DeletedVaultScope(scope, location.Name, id.Name);
                if (!Same(id, candidate.ResourceId)) throw new ControlledTransport.BoundaryException();
                return ObserveDeleted(candidate, resource.Data);
            }, cancellationToken);
    }

    /// <summary>Reads native private-connection state without establishing network reachability.</summary>
    /// <param name="scope">The exact connection record.</param>
    /// <param name="cancellationToken">Cancels the read and propagates caller cancellation.</param>
    /// <returns>Validated metadata, Absent for native no-content, or a bounded failure.</returns>
    /// <exception cref="ArgumentNullException">The scope is null.</exception>
    /// <exception cref="OperationCanceledException">Caller cancellation was observed.</exception>
    public ValueTask<SecretOutcome<PrivateConnectionObservation>> GetPrivateConnectionAsync(PrivateConnectionScope scope,
        CancellationToken cancellationToken = default)
    {
        ArgumentNullException.ThrowIfNull(scope);
        return Read(ArmCallTarget.At(ArmMethodContracts.PrivateConnectionGet, scope), async (client, token) => ObserveConnection(scope,
            (await client.GetKeyVaultPrivateEndpointConnectionResource(new ResourceIdentifier(scope.ResourceId))
                .GetAsync(token).ConfigureAwait(false)).Value.Data), cancellationToken, [200, 204]);
    }

    /// <summary>Collects bounded private-connection metadata for one vault.</summary>
    /// <param name="scope">The owning vault.</param>
    /// <param name="limits">Local enumeration budgets.</param>
    /// <param name="cancellationToken">Cancels enumeration and propagates caller cancellation.</param>
    /// <returns>Connection observations with explicit completeness; endpoint reachability is unverified.</returns>
    /// <exception cref="ArgumentNullException">The scope or limits is null.</exception>
    /// <exception cref="OperationCanceledException">Caller cancellation was observed.</exception>
    public ValueTask<ManagementInventory<PrivateConnectionObservation>> ListPrivateConnectionsAsync(VaultScope scope,
        CollectionLimits limits, CancellationToken cancellationToken = default)
    {
        ArgumentNullException.ThrowIfNull(scope);
        return Collect(ArmCallTarget.Below(ArmMethodContracts.PrivateConnectionList, scope), limits,
            (client, token) => client.GetKeyVaultResource(new ResourceIdentifier(scope.ResourceId))
                .GetKeyVaultPrivateEndpointConnections().GetAllAsync(token),
            resource => ObserveConnection(new PrivateConnectionScope(scope, resource.Id.Name), resource.Data),
            cancellationToken);
    }

    /// <summary>Collects bounded native private-link requirements without provisioning endpoints or DNS.</summary>
    /// <param name="scope">The selected vault.</param>
    /// <param name="limits">Local enumeration budgets.</param>
    /// <param name="cancellationToken">Cancels enumeration and propagates caller cancellation.</param>
    /// <returns>Copied resource requirements and explicit completeness.</returns>
    /// <exception cref="ArgumentNullException">The scope or limits is null.</exception>
    /// <exception cref="OperationCanceledException">Caller cancellation was observed.</exception>
    public ValueTask<ManagementInventory<PrivateLinkObservation>> ListPrivateLinkResourcesAsync(VaultScope scope,
        CollectionLimits limits, CancellationToken cancellationToken = default)
    {
        ArgumentNullException.ThrowIfNull(scope);
        var target = ArmCallTarget.Below(ArmMethodContracts.PrivateLinkList, scope);
        return Collect(target, limits,
            (client, token) => client.GetKeyVaultResource(new ResourceIdentifier(scope.ResourceId))
                .GetPrivateLinkResourcesAsync(token),
            resource =>
            {
                if (!Same(resource.Id, $"{target.Path}/{resource.Name}"))
                {
                    throw new ControlledTransport.BoundaryException();
                }

                return new PrivateLinkObservation(resource.Name, resource.GroupId,
                    resource.RequiredMembers, resource.RequiredZoneNames);
            }, cancellationToken);
    }

    /// <summary>Approves or rejects an existing connection. Does not provision a private endpoint.</summary>
    /// <param name="scope">The exact existing private-connection record.</param>
    /// <param name="state">Approved or Rejected; other states are not valid update instructions.</param>
    /// <param name="receipt">Unused client-prepared evidence for this scope and UpdatePrivateConnection.</param>
    /// <param name="cancellationToken">Cancels locally without undoing a dispatched state change.</param>
    /// <returns>A local operation handle, not proof of network reachability, or a bounded failure.</returns>
    /// <exception cref="ArgumentNullException">The scope or receipt is null.</exception>
    /// <exception cref="OperationCanceledException">Caller cancellation was observed; inspect retained receipt evidence.</exception>
    public ValueTask<SecretOutcome<ManagementOperation>> UpdatePrivateConnectionAsync(PrivateConnectionScope scope,
        PrivateConnectionState state, ManagementReceipt receipt, CancellationToken cancellationToken = default)
    {
        ArgumentNullException.ThrowIfNull(scope);
        if (state is not (PrivateConnectionState.Approved or PrivateConnectionState.Rejected))
        {
            return ValueTask.FromResult(SecretOutcome<ManagementOperation>.Failure(SecretStatus.Invalid));
        }

        return Mutate(scope, ManagementMutation.UpdatePrivateConnection, receipt, ArmCallTarget.At(ArmMethodContracts.PrivateConnectionUpdate, scope), RequestMethod.Put,
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

    /// <summary>Deletes a native private-connection record without provisioning or deleting the remote endpoint.</summary>
    /// <param name="scope">The exact connection record.</param>
    /// <param name="receipt">Unused client-prepared evidence for this scope and DeletePrivateConnection.</param>
    /// <param name="cancellationToken">Cancels locally without undoing a dispatched deletion.</param>
    /// <returns>A local operation handle, or a bounded failure without replay.</returns>
    /// <exception cref="ArgumentNullException">The scope or receipt is null.</exception>
    /// <exception cref="OperationCanceledException">Caller cancellation was observed; inspect retained receipt evidence.</exception>
    public ValueTask<SecretOutcome<ManagementOperation>> DeletePrivateConnectionAsync(PrivateConnectionScope scope,
        ManagementReceipt receipt, CancellationToken cancellationToken = default)
    {
        ArgumentNullException.ThrowIfNull(scope);
        return Mutate(scope, ManagementMutation.DeletePrivateConnection, receipt, ArmCallTarget.At(ArmMethodContracts.PrivateConnectionDelete, scope), RequestMethod.Delete,
            [200, 202, 204], async (client, transport, token) => ManagementOperation.From(
                await client.GetKeyVaultPrivateEndpointConnectionResource(new ResourceIdentifier(scope.ResourceId))
                    .DeleteAsync(WaitUntil.Started, token).ConfigureAwait(false), transport, _timeout, _time),
            cancellationToken);
    }

    private async ValueTask<ManagementInventory<T>> Collect<TResource, T>(ArmCallTarget target, CollectionLimits limits,
        Func<ArmClient, CancellationToken, AsyncPageable<TResource>> getPages, Func<TResource, T> project,
        CancellationToken cancellationToken, RequestMethod? method = null)
        where TResource : notnull where T : notnull
    {
        using var observation = new AzureManagementDiagnostics.Observation(AzureDiagnosticOperation.AdministrativeInventory, _time, cancellationToken);
        ArgumentNullException.ThrowIfNull(limits);
        using var deadline = new CancellationTokenSource(limits.Timeout, _time);
        using var linked = CancellationTokenSource.CreateLinkedTokenSource(cancellationToken, deadline.Token);
        var items = new List<T>();
        int pages = 0;
        var transport = Route(target, method ?? RequestMethod.Get, [200]);
        try
        {
            var iterator = getPages(_client, linked.Token)
                .AsPages(pageSizeHint: Math.Min(100, limits.MaximumItems)).GetAsyncEnumerator(linked.Token);
            await using var iteratorLifetime = iterator.ConfigureAwait(false);
            while (true)
            {
                using (AzureCallPipeline.Bind(transport))
                    if (!await iterator.MoveNextAsync().ConfigureAwait(false)) break;
                var page = iterator.Current;
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
                    return observation.Record(new ManagementInventory<T>(items, false, SecretStatus.Unsupported));
                }

                if (complete || pages >= limits.MaximumPages || items.Count >= limits.MaximumItems)
                {
                    return observation.Record(new ManagementInventory<T>(items, complete, SecretStatus.Success));
                }
            }

            return observation.Record(transport.HasContinuation ? new ManagementInventory<T>(items, false, SecretStatus.Unsupported) :
                new ManagementInventory<T>(items, true, SecretStatus.Success));
        }
        catch (OperationCanceledException)
        {
            observation.Cancel(deadline.IsCancellationRequested);
            if (cancellationToken.IsCancellationRequested)
            {
                foreach (var attribute in items.OfType<NotificationDeliveryAttribute>()) attribute.Dispose();
            }
            cancellationToken.ThrowIfCancellationRequested();
            return observation.Record(new ManagementInventory<T>(items, false, SecretStatus.Unavailable));
        }
        catch (Exception exception)
        {
            if (deadline.IsCancellationRequested) observation.Cancel(true);
            if (cancellationToken.IsCancellationRequested)
            {
                foreach (var attribute in items.OfType<NotificationDeliveryAttribute>()) attribute.Dispose();
            }
            cancellationToken.ThrowIfCancellationRequested();
            return observation.Record(new ManagementInventory<T>(items, false, ControlledTransport.Failure(exception)));
        }
    }

    private static bool Same(ResourceIdentifier? actual, string expected) =>
        actual is not null && actual.ToString().Equals(expected, StringComparison.OrdinalIgnoreCase);

    private static VaultScope ParseVault(ResourceIdentifier id, SubscriptionScope subscription, ResourceGroupScope? group = null)
    {
        if (id.ResourceType != KeyVaultResource.ResourceType || id.ResourceGroupName is not { } groupName)
            throw new ControlledTransport.BoundaryException();

        var candidate = new VaultScope(group ?? new ResourceGroupScope(subscription, groupName), id.Name);
        if (!Same(id, candidate.ResourceId)) throw new ControlledTransport.BoundaryException();
        return candidate;
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
