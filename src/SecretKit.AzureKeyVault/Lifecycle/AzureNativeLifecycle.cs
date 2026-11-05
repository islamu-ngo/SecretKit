using System.Security.Cryptography;
using Azure;
using Azure.Core;
using Azure.Security.KeyVault.Secrets;
using SecretKit.Core;

namespace SecretKit.AzureKeyVault;

public sealed partial class AzureKeyVaultClient
{
    /// <summary>
    /// Retrieves an exact native version including disabled/expired metadata, unlike consumption ReadAsync.
    /// The service can still deny value access. Returned material is independently owned.
    /// </summary>
    /// <param name="target">This client's exact-version reference; an unversioned reference is unsupported.</param>
    /// <param name="cancellationToken">Cancels acquisition and propagates cancellation.</param>
    /// <returns>A caller-disposable read with native validity metadata, or a bounded failure.</returns>
    /// <exception cref="ArgumentNullException">The target is null.</exception>
    /// <exception cref="OperationCanceledException">Cancellation was observed.</exception>
    public async ValueTask<SecretOutcome<SecretRead>> GetSecretVersionAsync(
        SecretReference target, CancellationToken cancellationToken = default)
    {
        using var observation = new AzureDiagnostics.Observation(AzureDiagnosticOperation.NativeRead, _time, cancellationToken);
        try
        {
            return observation.Record(await GetSecretVersionAsyncCore(target, cancellationToken).ConfigureAwait(false));
        }
        catch (OperationCanceledException)
        {
            observation.Cancel();
            throw;
        }
    }

    private async ValueTask<SecretOutcome<SecretRead>> GetSecretVersionAsyncCore(
        SecretReference target, CancellationToken cancellationToken = default)
    {
        ArgumentNullException.ThrowIfNull(target);
        cancellationToken.ThrowIfCancellationRequested();
        if (!NativeTarget(target, out var address))
        {
            return SecretOutcome<SecretRead>.Failure(SecretStatus.Invalid);
        }
        if (address.Version is null)
        {
            return SecretOutcome<SecretRead>.Failure(SecretStatus.Unsupported);
        }
        try
        {
            var secret = (await _client.GetSecretAsync(address.Name, address.Version, cancellationToken)
                .ConfigureAwait(false)).Value;
            ValidateProperties(secret.Properties, address, true);
            cancellationToken.ThrowIfCancellationRequested();
            if (secret.Value is null)
            {
                return SecretOutcome<SecretRead>.Failure(SecretStatus.Unknown);
            }
            return SecretOutcome<SecretRead>.Success(new SecretRead(SecretMaterial.FromText(secret.Value),
                Observe(secret.Properties, _time.GetUtcNow())));
        }
        catch (OperationCanceledException)
        {
            throw new OperationCanceledException(cancellationToken);
        }
        catch (Exception exception)
        {
            cancellationToken.ThrowIfCancellationRequested();
            return SecretOutcome<SecretRead>.Failure(Status(exception));
        }
    }

    /// <summary>Collects bounded version metadata for one name without acquiring values or creating a remote snapshot.</summary>
    /// <param name="target">This client's unversioned secret reference.</param>
    /// <param name="scope">Page/item bounds under this client's authority.</param>
    /// <param name="cancellationToken">Cancels enumeration and propagates cancellation.</param>
    /// <returns>Native metadata with explicit completeness, or a bounded failure.</returns>
    /// <exception cref="ArgumentNullException">The target or scope is null.</exception>
    /// <exception cref="OperationCanceledException">Cancellation was observed.</exception>
    public async ValueTask<SecretOutcome<AzureNativeInventory>> GetSecretVersionsAsync(
        SecretReference target, AzureInventoryScope scope, CancellationToken cancellationToken = default)
    {
        using var observation = new AzureDiagnostics.Observation(AzureDiagnosticOperation.NativeInventory, _time, cancellationToken);
        try
        {
            return observation.Record(await GetSecretVersionsAsyncCore(target, scope, cancellationToken).ConfigureAwait(false));
        }
        catch (OperationCanceledException)
        {
            observation.Cancel();
            throw;
        }
    }

    private async ValueTask<SecretOutcome<AzureNativeInventory>> GetSecretVersionsAsyncCore(
        SecretReference target, AzureInventoryScope scope, CancellationToken cancellationToken = default)
    {
        ArgumentNullException.ThrowIfNull(target);
        ArgumentNullException.ThrowIfNull(scope);
        cancellationToken.ThrowIfCancellationRequested();
        if (!NativeTarget(target, out var address) || !scope.BelongsTo(Authority))
        {
            return SecretOutcome<AzureNativeInventory>.Failure(SecretStatus.Invalid);
        }
        if (address.Version is not null)
        {
            return SecretOutcome<AzureNativeInventory>.Failure(SecretStatus.Unsupported);
        }
        return await CollectNativeAsync(_client.GetPropertiesOfSecretVersionsAsync(address.Name, cancellationToken),
            scope, $"/secrets/{address.Name}/versions",
            properties => Metadata(properties, address, true), cancellationToken).ConfigureAwait(false);
    }

    /// <summary>Updates exact-version attributes without changing the value; null fields are omitted and empty tags clear tags.</summary>
    /// <param name="request">The bounded exact-version patch; conditional writes are unsupported.</param>
    /// <param name="receipt">Unused evidence issued by this client for the exact patch target.</param>
    /// <param name="cancellationToken">Cancels locally; dispatch uncertainty remains in the receipt.</param>
    /// <returns>Validated resulting metadata, or a bounded failure without mutation replay.</returns>
    /// <exception cref="ArgumentNullException">The request or receipt is null.</exception>
    /// <exception cref="OperationCanceledException">Cancellation was observed; the attempt may already be consumed.</exception>
    public async ValueTask<SecretOutcome<AzureSecretMetadata>> UpdatePropertiesAsync(
        AzureUpdatePropertiesRequest request, MutationReceipt receipt, CancellationToken cancellationToken = default)
    {
        using var observation = new AzureDiagnostics.Observation(AzureDiagnosticOperation.NativeMutation, _time, cancellationToken, receipt);
        try
        {
            return observation.Record(await UpdatePropertiesAsyncCore(request, receipt, cancellationToken).ConfigureAwait(false));
        }
        catch (OperationCanceledException)
        {
            observation.Cancel();
            throw;
        }
    }

    private ValueTask<SecretOutcome<AzureSecretMetadata>> UpdatePropertiesAsyncCore(
        AzureUpdatePropertiesRequest request, MutationReceipt receipt, CancellationToken cancellationToken = default)
    {
        ArgumentNullException.ThrowIfNull(request);
        return MutateNativeAsync(request.Target, receipt, true, request.Precondition, RequestMethod.Patch,
            address => $"/secrets/{address.Name}/{address.Version}", async (client, address) =>
            {
                var properties = new SecretProperties(new Uri(_vault, $"secrets/{address.Name}/{address.Version}"))
                {
                    Enabled = request.Enabled,
                    NotBefore = request.NotBefore,
                    ExpiresOn = request.ExpiresOn,
                    ContentType = request.ContentType
                };
                if (request.Tags is not null)
                {
                    foreach (var tag in request.Tags)
                    {
                        properties.Tags.Add(tag.Key, tag.Value);
                    }
                }
                var updated = (await client.UpdateSecretPropertiesAsync(properties, cancellationToken)
                    .ConfigureAwait(false)).Value;
                return Metadata(updated, address, true);
            }, cancellationToken, clearTags: request.Tags is { Count: 0 });
    }

    /// <summary>Observes native soft-deleted metadata without recovering the secret.</summary>
    /// <param name="target">This client's unversioned reference to the deleted name.</param>
    /// <param name="cancellationToken">Cancels acquisition and propagates cancellation.</param>
    /// <returns>Validated deleted metadata, or a bounded failure.</returns>
    /// <exception cref="ArgumentNullException">The target is null.</exception>
    /// <exception cref="OperationCanceledException">Cancellation was observed.</exception>
    public async ValueTask<SecretOutcome<AzureSecretMetadata>> GetDeletedSecretAsync(
        SecretReference target, CancellationToken cancellationToken = default)
    {
        using var observation = new AzureDiagnostics.Observation(AzureDiagnosticOperation.NativeRead, _time, cancellationToken);
        try
        {
            return observation.Record(await GetDeletedSecretAsyncCore(target, cancellationToken).ConfigureAwait(false));
        }
        catch (OperationCanceledException)
        {
            observation.Cancel();
            throw;
        }
    }

    private async ValueTask<SecretOutcome<AzureSecretMetadata>> GetDeletedSecretAsyncCore(
        SecretReference target, CancellationToken cancellationToken = default)
    {
        ArgumentNullException.ThrowIfNull(target);
        cancellationToken.ThrowIfCancellationRequested();
        if (!NativeTarget(target, out var address))
        {
            return SecretOutcome<AzureSecretMetadata>.Failure(SecretStatus.Invalid);
        }
        if (address.Version is not null)
        {
            return SecretOutcome<AzureSecretMetadata>.Failure(SecretStatus.Unsupported);
        }
        try
        {
            var deleted = (await _client.GetDeletedSecretAsync(address.Name, cancellationToken)
                .ConfigureAwait(false)).Value;
            var result = DeletedMetadata(deleted, address);
            cancellationToken.ThrowIfCancellationRequested();
            return SecretOutcome<AzureSecretMetadata>.Success(result);
        }
        catch (OperationCanceledException)
        {
            throw new OperationCanceledException(cancellationToken);
        }
        catch (Exception exception)
        {
            cancellationToken.ThrowIfCancellationRequested();
            return SecretOutcome<AzureSecretMetadata>.Failure(Status(exception));
        }
    }

    /// <summary>Collects bounded soft-deleted metadata without secret values or a remote snapshot.</summary>
    /// <param name="scope">Page/item bounds under this client's authority.</param>
    /// <param name="cancellationToken">Cancels enumeration and propagates cancellation.</param>
    /// <returns>Deleted-secret observations with explicit completeness, or a bounded failure.</returns>
    /// <exception cref="ArgumentNullException">The scope is null.</exception>
    /// <exception cref="OperationCanceledException">Cancellation was observed.</exception>
    public async ValueTask<SecretOutcome<AzureNativeInventory>> GetDeletedSecretsAsync(
        AzureInventoryScope scope, CancellationToken cancellationToken = default)
    {
        using var observation = new AzureDiagnostics.Observation(AzureDiagnosticOperation.NativeInventory, _time, cancellationToken);
        try
        {
            return observation.Record(await GetDeletedSecretsAsyncCore(scope, cancellationToken).ConfigureAwait(false));
        }
        catch (OperationCanceledException)
        {
            observation.Cancel();
            throw;
        }
    }

    private ValueTask<SecretOutcome<AzureNativeInventory>> GetDeletedSecretsAsyncCore(
        AzureInventoryScope scope, CancellationToken cancellationToken = default)
    {
        ArgumentNullException.ThrowIfNull(scope);
        cancellationToken.ThrowIfCancellationRequested();
        if (!scope.BelongsTo(Authority))
        {
            return ValueTask.FromResult(SecretOutcome<AzureNativeInventory>.Failure(SecretStatus.Invalid));
        }
        return CollectNativeAsync(_client.GetDeletedSecretsAsync(cancellationToken), scope, "/deletedsecrets",
            deleted => DeletedMetadata(deleted, null), cancellationToken);
    }

    /// <summary>Starts all-version deletion. Success contains Pending evidence, without a status request.</summary>
    /// <param name="target">This client's unversioned secret reference.</param>
    /// <param name="receipt">Unused client-issued evidence for this exact target; one attempt consumes it.</param>
    /// <param name="cancellationToken">Cancels locally without undoing a dispatched deletion.</param>
    /// <returns>An acknowledged start with a local status selector, or a bounded failure.</returns>
    /// <exception cref="ArgumentNullException">The target or receipt is null.</exception>
    /// <exception cref="OperationCanceledException">Cancellation was observed; inspect retained evidence.</exception>
    public async ValueTask<SecretOutcome<AzureLifecycleResult>> StartDeleteSecretAsync(
        SecretReference target, MutationReceipt receipt, CancellationToken cancellationToken = default)
    {
        using var observation = new AzureDiagnostics.Observation(AzureDiagnosticOperation.NativeMutation, _time, cancellationToken, receipt);
        try
        {
            return observation.Record(await StartDeleteSecretAsyncCore(target, receipt, cancellationToken).ConfigureAwait(false));
        }
        catch (OperationCanceledException)
        {
            observation.Cancel();
            throw;
        }
    }

    private ValueTask<SecretOutcome<AzureLifecycleResult>> StartDeleteSecretAsyncCore(
        SecretReference target, MutationReceipt receipt, CancellationToken cancellationToken = default) =>
        MutateNativeAsync(target, receipt, false, AzureSetSecretPrecondition.None, RequestMethod.Delete,
            address => $"/secrets/{address.Name}", async (client, address) =>
            {
                var operation = await client.StartDeleteSecretAsync(address.Name, cancellationToken).ConfigureAwait(false);
                var metadata = DeletedMetadata(operation.Value, address);
                return new AzureLifecycleResult(new AzureLifecycleOperation(target, AzureLifecycleKind.Delete),
                    AzureLifecycleState.Pending, metadata);
            }, cancellationToken, pending: true);

    /// <summary>Starts native recovery. No automatic wait, background worker or recovery replay.</summary>
    /// <param name="target">This client's unversioned reference to the deleted name.</param>
    /// <param name="receipt">Unused client-issued evidence for this exact target; one attempt consumes it.</param>
    /// <param name="cancellationToken">Cancels locally without undoing a dispatched recovery.</param>
    /// <returns>An acknowledged pending start, or a bounded failure.</returns>
    /// <exception cref="ArgumentNullException">The target or receipt is null.</exception>
    /// <exception cref="OperationCanceledException">Cancellation was observed; inspect retained evidence.</exception>
    public async ValueTask<SecretOutcome<AzureLifecycleResult>> StartRecoverDeletedSecretAsync(
        SecretReference target, MutationReceipt receipt, CancellationToken cancellationToken = default)
    {
        using var observation = new AzureDiagnostics.Observation(AzureDiagnosticOperation.NativeMutation, _time, cancellationToken, receipt);
        try
        {
            return observation.Record(await StartRecoverDeletedSecretAsyncCore(target, receipt, cancellationToken).ConfigureAwait(false));
        }
        catch (OperationCanceledException)
        {
            observation.Cancel();
            throw;
        }
    }

    private ValueTask<SecretOutcome<AzureLifecycleResult>> StartRecoverDeletedSecretAsyncCore(
        SecretReference target, MutationReceipt receipt, CancellationToken cancellationToken = default) =>
        MutateNativeAsync(target, receipt, false, AzureSetSecretPrecondition.None, RequestMethod.Post,
            address => $"/deletedsecrets/{address.Name}/recover", async (client, address) =>
            {
                var operation = await client.StartRecoverDeletedSecretAsync(address.Name, cancellationToken).ConfigureAwait(false);
                var metadata = Metadata(operation.Value, address, true);
                return new AzureLifecycleResult(new AzureLifecycleOperation(target, AzureLifecycleKind.Recover),
                    AzureLifecycleState.Pending, metadata);
            }, cancellationToken, pending: true);

    /// <summary>
    /// One explicit native availability observation following an acknowledged start.
    /// A matching object is observed Applied, not proof that no concurrent actor changed it.
    /// The start receipt remains its original Pending evidence.
    /// </summary>
    /// <param name="operation">The local selector returned by this client's acknowledged lifecycle start.</param>
    /// <param name="cancellationToken">Cancels this explicit observation.</param>
    /// <returns>Applied when the expected object is observed, Pending on absence, or a bounded failure.</returns>
    /// <exception cref="ArgumentNullException">The operation is null.</exception>
    /// <exception cref="OperationCanceledException">Cancellation was observed.</exception>
    public async ValueTask<SecretOutcome<AzureLifecycleResult>> CheckLifecycleStatusAsync(
        AzureLifecycleOperation operation, CancellationToken cancellationToken = default)
    {
        using var observation = new AzureDiagnostics.Observation(AzureDiagnosticOperation.LifecycleCheck, _time, cancellationToken);
        try
        {
            return observation.Record(await CheckLifecycleStatusAsyncCore(operation, cancellationToken).ConfigureAwait(false));
        }
        catch (OperationCanceledException)
        {
            observation.Cancel();
            throw;
        }
    }

    private async ValueTask<SecretOutcome<AzureLifecycleResult>> CheckLifecycleStatusAsyncCore(
        AzureLifecycleOperation operation, CancellationToken cancellationToken = default)
    {
        ArgumentNullException.ThrowIfNull(operation);
        cancellationToken.ThrowIfCancellationRequested();
        if (!NativeTarget(operation.Target, out var address))
        {
            return SecretOutcome<AzureLifecycleResult>.Failure(SecretStatus.Invalid);
        }
        try
        {
            AzureSecretMetadata metadata;
            if (operation.Kind == AzureLifecycleKind.Delete)
            {
                var deleted = (await _client.GetDeletedSecretAsync(address.Name, cancellationToken)
                    .ConfigureAwait(false)).Value;
                metadata = DeletedMetadata(deleted, address);
            }
            else
            {
                var secret = (await _client.GetSecretAsync(address.Name, cancellationToken: cancellationToken)
                    .ConfigureAwait(false)).Value;
                metadata = Metadata(secret.Properties, address, true);
            }
            cancellationToken.ThrowIfCancellationRequested();
            return SecretOutcome<AzureLifecycleResult>.Success(
                new AzureLifecycleResult(operation, AzureLifecycleState.Applied, metadata));
        }
        catch (OperationCanceledException)
        {
            throw new OperationCanceledException(cancellationToken);
        }
        catch (RequestFailedException exception) when (exception.Status == 404)
        {
            cancellationToken.ThrowIfCancellationRequested();
            return SecretOutcome<AzureLifecycleResult>.Success(
                new AzureLifecycleResult(operation, AzureLifecycleState.Pending, null));
        }
        catch (Exception exception)
        {
            cancellationToken.ThrowIfCancellationRequested();
            return SecretOutcome<AzureLifecycleResult>.Failure(Status(exception));
        }
    }

    /// <summary>Requests permanent removal of a deleted secret without retrying; provider retention protections remain authoritative.</summary>
    /// <param name="target">This client's unversioned deleted-secret reference.</param>
    /// <param name="receipt">Unused client-issued evidence for this exact target.</param>
    /// <param name="cancellationToken">Cancels locally without establishing that purge did not occur.</param>
    /// <returns>The native acknowledgement, not proof of immediate global disappearance, or a bounded failure.</returns>
    /// <exception cref="ArgumentNullException">The target or receipt is null.</exception>
    /// <exception cref="OperationCanceledException">Cancellation was observed; inspect retained evidence.</exception>
    public async ValueTask<SecretOutcome<AzurePurgeResult>> PurgeDeletedSecretAsync(
        SecretReference target, MutationReceipt receipt, CancellationToken cancellationToken = default)
    {
        using var observation = new AzureDiagnostics.Observation(AzureDiagnosticOperation.NativeMutation, _time, cancellationToken, receipt);
        try
        {
            return observation.Record(await PurgeDeletedSecretAsyncCore(target, receipt, cancellationToken).ConfigureAwait(false));
        }
        catch (OperationCanceledException)
        {
            observation.Cancel();
            throw;
        }
    }

    private ValueTask<SecretOutcome<AzurePurgeResult>> PurgeDeletedSecretAsyncCore(
        SecretReference target, MutationReceipt receipt, CancellationToken cancellationToken = default) =>
        MutateNativeAsync(target, receipt, false, AzureSetSecretPrecondition.None, RequestMethod.Delete,
            address => $"/deletedsecrets/{address.Name}", async (client, address) =>
            {
                var response = await client.PurgeDeletedSecretAsync(address.Name, cancellationToken).ConfigureAwait(false);
                if (response.Status != 204)
                {
                    throw new NativeCoordinateException();
                }
                return new AzurePurgeResult();
            }, cancellationToken);

    /// <summary>Acquires an independently owned opaque all-version artifact; no mutation receipt is needed.</summary>
    /// <param name="target">This client's unversioned secret reference.</param>
    /// <param name="cancellationToken">Cancels acquisition; unpublished owned bytes are cleared.</param>
    /// <returns>A backup the caller must dispose, or a bounded failure. Azure controls restore eligibility.</returns>
    /// <exception cref="ArgumentNullException">The target is null.</exception>
    /// <exception cref="OperationCanceledException">Cancellation was observed.</exception>
    public async ValueTask<SecretOutcome<AzureSecretBackup>> BackupSecretAsync(
        SecretReference target, CancellationToken cancellationToken = default)
    {
        using var observation = new AzureDiagnostics.Observation(AzureDiagnosticOperation.Backup, _time, cancellationToken);
        try
        {
            return observation.Record(await BackupSecretAsyncCore(target, cancellationToken).ConfigureAwait(false));
        }
        catch (OperationCanceledException)
        {
            observation.Cancel();
            throw;
        }
    }

    private async ValueTask<SecretOutcome<AzureSecretBackup>> BackupSecretAsyncCore(
        SecretReference target, CancellationToken cancellationToken = default)
    {
        ArgumentNullException.ThrowIfNull(target);
        cancellationToken.ThrowIfCancellationRequested();
        if (!NativeTarget(target, out var address))
        {
            return SecretOutcome<AzureSecretBackup>.Failure(SecretStatus.Invalid);
        }
        if (address.Version is not null)
        {
            return SecretOutcome<AzureSecretBackup>.Failure(SecretStatus.Unsupported);
        }
        byte[]? bytes = null;
        try
        {
            bytes = (await _client.BackupSecretAsync(address.Name, cancellationToken).ConfigureAwait(false)).Value;
            cancellationToken.ThrowIfCancellationRequested();
            if (bytes is null || bytes.Length == 0 || bytes.Length > _maximumResponseBytes)
            {
                return SecretOutcome<AzureSecretBackup>.Failure(SecretStatus.Invalid);
            }
            return SecretOutcome<AzureSecretBackup>.Success(AzureSecretBackup.FromBytes(bytes));
        }
        catch (OperationCanceledException)
        {
            throw new OperationCanceledException(cancellationToken);
        }
        catch (Exception exception)
        {
            cancellationToken.ThrowIfCancellationRequested();
            return SecretOutcome<AzureSecretBackup>.Failure(Status(exception));
        }
        finally
        {
            if (bytes is not null)
            {
                CryptographicOperations.ZeroMemory(bytes);
            }
        }
    }

    /// <summary>Restores an opaque all-version artifact into this vault without rename, conditional write or replay.</summary>
    /// <param name="request">The expected unversioned target and borrowed backup, retained by the caller through execution.</param>
    /// <param name="receipt">Unused client-issued evidence for this exact expected target.</param>
    /// <param name="cancellationToken">Cancels locally without undoing an applied restore.</param>
    /// <returns>Validated restored metadata, or a bounded failure; an uncertain response does not authorize another restore.</returns>
    /// <exception cref="ArgumentNullException">The request or receipt is null.</exception>
    /// <exception cref="OperationCanceledException">Cancellation was observed; inspect retained evidence.</exception>
    public async ValueTask<SecretOutcome<AzureSecretMetadata>> RestoreSecretBackupAsync(
        AzureRestoreSecretRequest request, MutationReceipt receipt, CancellationToken cancellationToken = default)
    {
        using var observation = new AzureDiagnostics.Observation(AzureDiagnosticOperation.NativeMutation, _time, cancellationToken, receipt);
        try
        {
            return observation.Record(await RestoreSecretBackupAsyncCore(request, receipt, cancellationToken).ConfigureAwait(false));
        }
        catch (OperationCanceledException)
        {
            observation.Cancel();
            throw;
        }
    }

    private ValueTask<SecretOutcome<AzureSecretMetadata>> RestoreSecretBackupAsyncCore(
        AzureRestoreSecretRequest request, MutationReceipt receipt, CancellationToken cancellationToken = default)
    {
        ArgumentNullException.ThrowIfNull(request);
        return MutateNativeAsync(request.Target, receipt, false, request.Precondition, RequestMethod.Post,
            _ => "/secrets/restore", async (client, address) =>
            {
                byte[] bytes = request.Backup.Export();
                try
                {
                    if (bytes.Length > _maximumResponseBytes)
                    {
                        throw new ResponseBudgetExceededException();
                    }
                    var restored = (await client.RestoreSecretBackupAsync(bytes, cancellationToken)
                        .ConfigureAwait(false)).Value;
                    return Metadata(restored, address, true);
                }
                finally
                {
                    CryptographicOperations.ZeroMemory(bytes);
                }
            }, cancellationToken);
    }

    private bool NativeTarget(SecretReference target, out AzureSecretAddress address)
    {
        address = target.Address as AzureSecretAddress ?? null!;
        return target.BelongsTo(Authority) && address is not null;
    }

    private void ValidateProperties(SecretProperties properties, AzureSecretAddress? selected, bool requireVersion)
    {
        if (properties.Id is not { IsAbsoluteUri: true } id || !SameOrigin(_vault, id) ||
            id.Query.Length != 0 || string.IsNullOrEmpty(properties.Name) ||
            properties.Name.Length > 127 || !properties.Name.All(c => char.IsAsciiLetterOrDigit(c) || c == '-') ||
            (selected is not null && !string.Equals(properties.Name, selected.Name, StringComparison.OrdinalIgnoreCase)) ||
            (selected?.Version is not null && !string.Equals(properties.Version, selected.Version, StringComparison.OrdinalIgnoreCase)) ||
            (requireVersion && properties.Version is null) ||
            (properties.Version is not null && (properties.Version.Length != 32 || !properties.Version.All(char.IsAsciiHexDigit))) ||
            id.AbsolutePath != (properties.Version is null
                ? $"/secrets/{properties.Name}" : $"/secrets/{properties.Name}/{properties.Version}"))
        {
            throw new NativeCoordinateException();
        }
    }

    private AzureSecretMetadata Metadata(SecretProperties properties, AzureSecretAddress? selected,
        bool requireVersion)
    {
        ValidateProperties(properties, selected, requireVersion);
        return new AzureSecretMetadata(new SecretReference(Authority,
            new AzureSecretAddress(properties.Name, properties.Version)), properties.Enabled,
            properties.NotBefore, properties.ExpiresOn, properties.CreatedOn, properties.UpdatedOn,
            properties.ContentType, properties.Tags);
    }

    private AzureSecretMetadata DeletedMetadata(DeletedSecret deleted, AzureSecretAddress? selected)
    {
        ValidateProperties(deleted.Properties, selected, false);
        if (deleted.RecoveryId is not { IsAbsoluteUri: true } recovery ||
            !SameOrigin(_vault, recovery) || recovery.Query.Length != 0 ||
            recovery.AbsolutePath != $"/deletedsecrets/{deleted.Name}")
        {
            throw new NativeCoordinateException();
        }
        var properties = deleted.Properties;
        return new AzureSecretMetadata(new SecretReference(Authority,
            new AzureSecretAddress(properties.Name, properties.Version)), properties.Enabled,
            properties.NotBefore, properties.ExpiresOn, properties.CreatedOn, properties.UpdatedOn,
            properties.ContentType, properties.Tags, deleted.DeletedOn, deleted.ScheduledPurgeDate);
    }

    private async ValueTask<SecretOutcome<AzureNativeInventory>> CollectNativeAsync<T>(
        AsyncPageable<T> source, AzureInventoryScope scope, string path, Func<T, AzureSecretMetadata> project,
        CancellationToken cancellationToken) where T : notnull
    {
        var startedAt = _time.GetUtcNow();
        var items = new List<AzureSecretMetadata>();
        var pages = 0;
        var complete = false;
        try
        {
            await foreach (var page in source.AsPages(pageSizeHint: Math.Min(25, scope.MaximumItems)).ConfigureAwait(false))
            {
                cancellationToken.ThrowIfCancellationRequested();
                pages++;
                int remaining = scope.MaximumItems - items.Count;
                foreach (var value in page.Values)
                {
                    // Validate every returned coordinate, including rows beyond the publication bound.
                    var metadata = project(value);
                    if (items.Count < scope.MaximumItems)
                    {
                        items.Add(metadata);
                    }
                }
                complete = page.ContinuationToken is null && page.Values.Count <= remaining;
                if (page.ContinuationToken is null || pages == scope.MaximumPages || items.Count == scope.MaximumItems)
                {
                    break;
                }
                if (!Uri.TryCreate(page.ContinuationToken, UriKind.Absolute, out var next) ||
                    !SameOrigin(_vault, next) || next.AbsolutePath.TrimEnd('/') != path || !HasSelectedRevision(next))
                {
                    throw new NativeCoordinateException();
                }
            }
            return SecretOutcome<AzureNativeInventory>.Success(
                new AzureNativeInventory(items, startedAt, _time.GetUtcNow(), complete));
        }
        catch (OperationCanceledException)
        {
            throw new OperationCanceledException(cancellationToken);
        }
        catch (Exception exception)
        {
            cancellationToken.ThrowIfCancellationRequested();
            return SecretOutcome<AzureNativeInventory>.Failure(Status(exception));
        }
    }

    private async ValueTask<SecretOutcome<T>> MutateNativeAsync<T>(SecretReference target, MutationReceipt receipt,
        bool exactVersion, AzureSetSecretPrecondition precondition, RequestMethod method,
        Func<AzureSecretAddress, string> path, Func<SecretClient, AzureSecretAddress, Task<T>> execute,
        CancellationToken cancellationToken, bool pending = false, bool clearTags = false) where T : notnull
    {
        ArgumentNullException.ThrowIfNull(target);
        ArgumentNullException.ThrowIfNull(receipt);
        if (!NativeTarget(target, out var address) || !_receipts.Owns(receipt) || !receipt.IsFor(target) ||
            receipt.Evidence != DispatchEvidence.NotDispatched)
        {
            return SecretOutcome<T>.Failure(SecretStatus.Invalid);
        }
        lock (UsedReceipts)
        {
            if (UsedReceipts.TryGetValue(receipt, out _))
            {
                return SecretOutcome<T>.Failure(SecretStatus.Invalid);
            }
            UsedReceipts.Add(receipt, target);
        }
        cancellationToken.ThrowIfCancellationRequested();
        if (!Enum.IsDefined(precondition))
        {
            return SecretOutcome<T>.Failure(SecretStatus.Invalid);
        }
        if (exactVersion != (address.Version is not null) || precondition != AzureSetSecretPrecondition.None)
        {
            return SecretOutcome<T>.Failure(SecretStatus.Unsupported);
        }
        try
        {
            var result = await execute(CreateClient(receipt, target, path(address), method, clearTags), address).ConfigureAwait(false);
            _receipts.Record(receipt, pending ? DispatchEvidence.Pending : DispatchEvidence.Applied);
            cancellationToken.ThrowIfCancellationRequested();
            return SecretOutcome<T>.Success(result);
        }
        catch (OperationCanceledException)
        {
            throw new OperationCanceledException(cancellationToken);
        }
        catch (Exception exception)
        {
            cancellationToken.ThrowIfCancellationRequested();
            // A definitive service denial/conflict is an outcome, not an inferred capability.
            if (exception is RequestFailedException { Status: 400 or 403 or 404 or 409 } failure)
            {
                if (receipt.Evidence == DispatchEvidence.PossiblyDispatched)
                {
                    _receipts.Record(receipt, failure.Status == 409 ? DispatchEvidence.Conflict : DispatchEvidence.Rejected);
                }
                return SecretOutcome<T>.Failure(Status(failure));
            }
            return SecretOutcome<T>.Failure(receipt.Evidence == DispatchEvidence.PossiblyDispatched
                ? SecretStatus.Unknown : exception is ObjectDisposedException ? SecretStatus.Invalid : Status(exception));
        }
    }

    private sealed class NativeCoordinateException : IOException
    {
        public NativeCoordinateException() : base("Provider coordinates did not match the selected operation.") { }
    }
}
