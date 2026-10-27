using System.Buffers;
using System.Globalization;
using System.Net;
using System.Net.Http.Headers;
using System.Text.Json;
using System.Text.Json.Serialization;
using Refit;
using SecretKit.Core;

namespace SecretKit.Infisical;

/// <summary>
/// Explicit native lifecycle in one exact scope. Token source and injected handler remain host-owned.
/// Safe networking is the default; explicit host-controlled pipelines retain host policy.
/// No automatic leases, cleanup requests, persistence, fallback or background work.
/// </summary>
public sealed class InfisicalDynamicClient : IAsyncDisposable
{
    private readonly Uri _origin;
    private readonly HttpClient _http;
    private readonly InfisicalTransportBinding _binding;
    private readonly IInfisicalTokenSource _tokens;
    private readonly IInfisicalDynamicWire _wire;
    private readonly TimeProvider _time;
    private readonly int _byteLimit;
    private readonly int _maximumItems;
    private readonly object _gate = new();
    private readonly CancellationTokenSource _shutdown = new();
    private readonly TimeSpan _shutdownTimeout;
    private TaskCompletionSource? _drained;
    private Task? _disposeTask;
    private int _active;
    private bool _disposed;

    public InfisicalDynamicClient(Uri origin, IInfisicalTokenSource tokens, InfisicalDynamicScope scope,
        InfisicalNetworkOptions? network = null, TimeProvider? timeProvider = null,
        int maximumItems = 128)
    {
        ArgumentNullException.ThrowIfNull(origin);
        ArgumentNullException.ThrowIfNull(tokens);
        ArgumentNullException.ThrowIfNull(scope);
        network ??= new InfisicalNetworkOptions();
        InfisicalTransportBinding.ValidateOrigin(origin, network);
        if (network.MaximumResponseBytes is < 1024 or > 16 * 1024 * 1024 ||
            maximumItems is < 1 or > 1024 || network.ShutdownTimeout <= TimeSpan.Zero ||
            network.ShutdownTimeout > TimeSpan.FromMinutes(1))
        {
            throw new ArgumentException("Invalid native lifecycle budget.");
        }
        _origin = origin;
        _tokens = tokens;
        Scope = scope;
        _time = timeProvider ?? TimeProvider.System;
        _byteLimit = network.MaximumResponseBytes;
        _maximumItems = maximumItems;
        _shutdownTimeout = network.ShutdownTimeout;
        _binding = new(origin, network);
        _http = _binding.Client;
        _wire = RestService.For<IInfisicalDynamicWire>(_binding.Requests, new RefitSettings
        {
            CaptureMethodArguments = false,
            CaptureRequestContent = false
        });
    }

    [JsonIgnore] public InfisicalDynamicScope Scope { get; }
    public InfisicalDynamicTarget Definition(string name) => new(this, name);

    public async ValueTask<SecretOutcome<InfisicalNativeList<InfisicalDynamicDefinition>>> ListDefinitionsAsync(
        CancellationToken cancellationToken = default)
    {
        SecretOutcome<JsonDocument> response = await SendAsync(
            (_, _, token) => _wire.ListDefinitionsAsync(Scope.ProjectSlug, Scope.EnvironmentSlug, Scope.Path, token),
            null, null, cancellationToken).ConfigureAwait(false);
        if (!response.IsSuccess)
        {
            return SecretOutcome<InfisicalNativeList<InfisicalDynamicDefinition>>.Failure(response.Status);
        }
        using JsonDocument document = response.Value;
        if (!Array(document.RootElement, "dynamicSecrets", out JsonElement items) ||
            items.GetArrayLength() > _maximumItems)
        {
            return SecretOutcome<InfisicalNativeList<InfisicalDynamicDefinition>>.Failure(SecretStatus.Invalid);
        }
        var definitions = new List<InfisicalDynamicDefinition>();
        var ids = new HashSet<Guid>();
        var names = new HashSet<string>(StringComparer.Ordinal);
        foreach (JsonElement item in items.EnumerateArray())
        {
            cancellationToken.ThrowIfCancellationRequested();
            string? name = Text(item, "name");
            if (!ValidName(name) || !TryDefinition(item, Definition(name!), null, out InfisicalDynamicDefinition? definition) ||
                !ids.Add(definition!.Id) || !names.Add(name!))
            {
                return SecretOutcome<InfisicalNativeList<InfisicalDynamicDefinition>>.Failure(SecretStatus.Invalid);
            }
            definitions.Add(definition);
        }
        return SecretOutcome<InfisicalNativeList<InfisicalDynamicDefinition>>.Success(new(definitions, true));
    }

    public async ValueTask<SecretOutcome<InfisicalDynamicDefinition>> InspectDefinitionAsync(
        InfisicalDynamicTarget target, CancellationToken cancellationToken = default)
    {
        ArgumentNullException.ThrowIfNull(target);
        cancellationToken.ThrowIfCancellationRequested();
        if (target.Owner != this)
        {
            return SecretOutcome<InfisicalDynamicDefinition>.Failure(SecretStatus.Invalid);
        }
        SecretOutcome<JsonDocument> response = await SendAsync(
            (_, _, token) => _wire.InspectDefinitionAsync(target.Name, Scope.ProjectSlug, Scope.EnvironmentSlug, Scope.Path, token),
            null, null, cancellationToken).ConfigureAwait(false);
        return DefinitionResult(response, target, null, null, cancellationToken);
    }

    public async ValueTask<SecretOutcome<InfisicalDynamicDefinition>> CreateDefinitionAsync(
        InfisicalDynamicTarget target, InfisicalDynamicProfile profile, InfisicalLeaseDuration defaultTtl,
        InfisicalLeaseDuration? maximumTtl, InfisicalDynamicMutationReceipt receipt,
        CancellationToken cancellationToken = default, NativeDynamicDefinitionOptions? options = null)
    {
        ArgumentNullException.ThrowIfNull(profile);
        ArgumentNullException.ThrowIfNull(defaultTtl);
        if (!ValidMutation(target, null, receipt, InfisicalDynamicOperation.CreateDefinition, cancellationToken) ||
            maximumTtl?.Duration < defaultTtl.Duration)
        {
            return SecretOutcome<InfisicalDynamicDefinition>.Failure(SecretStatus.Invalid);
        }
        byte[] body = Body(writer =>
        {
            writer.WriteString("name", target.Name);
            writer.WriteString("defaultTTL", defaultTtl.Wire);
            if (maximumTtl is not null)
            {
                writer.WriteString("maxTTL", maximumTtl.Wire);
            }
            writer.WriteStartObject("provider");
            writer.WriteString("type", profile.WireType);
            writer.WriteStartObject("inputs");
            profile.WriteInputs(writer);
            writer.WriteEndObject();
            writer.WriteEndObject();
            options?.Write(writer);
        });
        SecretOutcome<JsonDocument> response = await SendAsync(
            (content, mutation, token) => _wire.CreateDefinitionAsync(content!, mutation!, token),
            body, receipt, cancellationToken).ConfigureAwait(false);
        return DefinitionResult(response, target, null, receipt, cancellationToken, profile.Provider);
    }

    /// <summary>Replaces TTL policy, including an explicit null maximum.</summary>
    public async ValueTask<SecretOutcome<InfisicalDynamicDefinition>> UpdateDefinitionPolicyAsync(
        InfisicalDynamicDefinition definition, InfisicalLeaseDuration defaultTtl,
        InfisicalLeaseDuration? maximumTtl, InfisicalDynamicMutationReceipt receipt,
        CancellationToken cancellationToken = default)
    {
        ArgumentNullException.ThrowIfNull(definition);
        ArgumentNullException.ThrowIfNull(defaultTtl);
        return await UpdateDefinitionAsync(definition, new NativeDynamicDefinitionPatch(defaultTtl, maximumTtl,
            clearMaximumTtl: maximumTtl is null), receipt, cancellationToken).ConfigureAwait(false);
    }

    public async ValueTask<SecretOutcome<InfisicalDynamicDefinition>> UpdateDefinitionAsync(
        InfisicalDynamicDefinition definition, NativeDynamicDefinitionPatch patch,
        InfisicalDynamicMutationReceipt receipt, CancellationToken cancellationToken = default)
    {
        ArgumentNullException.ThrowIfNull(definition);
        ArgumentNullException.ThrowIfNull(patch);
        if (!ValidMutation(definition.Target, null, receipt, InfisicalDynamicOperation.UpdateDefinition, cancellationToken) ||
            (patch.Inputs is not null && patch.Inputs.Provider != definition.Provider) ||
            (!patch.ClearMaximumTtl &&
                (patch.MaximumTtl ?? definition.MaximumTtl)?.Duration < (patch.DefaultTtl ?? definition.DefaultTtl).Duration))
        {
            return SecretOutcome<InfisicalDynamicDefinition>.Failure(SecretStatus.Invalid);
        }
        byte[] body = Body(writer =>
        {
            writer.WriteStartObject("data");
            patch.Write(writer);
            writer.WriteEndObject();
        });
        SecretOutcome<JsonDocument> response = await SendAsync(
            (content, mutation, token) => _wire.UpdateDefinitionAsync(definition.Target.Name, content!, mutation!, token),
            body, receipt, cancellationToken).ConfigureAwait(false);
        InfisicalDynamicTarget returnedTarget = patch.NewName is null ? definition.Target : Definition(patch.NewName);
        return DefinitionResult(response, returnedTarget, definition.Id, receipt, cancellationToken, definition.Provider);
    }

    public async ValueTask<SecretOutcome<InfisicalDynamicDeletion>> DeleteDefinitionAsync(
        InfisicalDynamicDefinition definition, InfisicalDynamicMutationReceipt receipt,
        bool forceRecordRemoval = false, CancellationToken cancellationToken = default)
    {
        ArgumentNullException.ThrowIfNull(definition);
        if (!ValidMutation(definition.Target, null, receipt, InfisicalDynamicOperation.DeleteDefinition, cancellationToken))
        {
            return SecretOutcome<InfisicalDynamicDeletion>.Failure(SecretStatus.Invalid);
        }
        SecretOutcome<JsonDocument> response = await SendAsync(
            (content, mutation, token) => _wire.DeleteDefinitionAsync(definition.Target.Name, content!, mutation!, token),
            Body(writer => writer.WriteBoolean("isForced", forceRecordRemoval)), receipt,
            cancellationToken).ConfigureAwait(false);
        SecretOutcome<InfisicalDynamicDefinition> result =
            DefinitionResult(response, definition.Target, definition.Id, receipt, cancellationToken, definition.Provider);
        return result.IsSuccess
            ? SecretOutcome<InfisicalDynamicDeletion>.Success(new(forceRecordRemoval, result.Value.Status))
            : SecretOutcome<InfisicalDynamicDeletion>.Failure(result.Status);
    }

    public async ValueTask<SecretOutcome<InfisicalNativeList<InfisicalLeaseObservation>>> ListLeasesAsync(
        InfisicalDynamicDefinition definition, CancellationToken cancellationToken = default)
    {
        ArgumentNullException.ThrowIfNull(definition);
        cancellationToken.ThrowIfCancellationRequested();
        if (definition.Target.Owner != this)
        {
            return SecretOutcome<InfisicalNativeList<InfisicalLeaseObservation>>.Failure(SecretStatus.Invalid);
        }
        SecretOutcome<JsonDocument> response = await SendAsync(
            (_, _, token) => _wire.ListLeasesAsync(definition.Target.Name, Scope.ProjectSlug, Scope.EnvironmentSlug, Scope.Path, token),
            null, null, cancellationToken).ConfigureAwait(false);
        if (!response.IsSuccess)
        {
            return SecretOutcome<InfisicalNativeList<InfisicalLeaseObservation>>.Failure(response.Status);
        }
        using JsonDocument document = response.Value;
        if (!Array(document.RootElement, "leases", out JsonElement items) || items.GetArrayLength() > _maximumItems)
        {
            return SecretOutcome<InfisicalNativeList<InfisicalLeaseObservation>>.Failure(SecretStatus.Invalid);
        }
        var observations = new List<InfisicalLeaseObservation>();
        var ids = new HashSet<Guid>();
        foreach (JsonElement item in items.EnumerateArray())
        {
            cancellationToken.ThrowIfCancellationRequested();
            if (!TryLease(item, definition, null, out InfisicalLeaseObservation? observation) ||
                !ids.Add(observation!.Reference.Id))
            {
                return SecretOutcome<InfisicalNativeList<InfisicalLeaseObservation>>.Failure(SecretStatus.Invalid);
            }
            observations.Add(observation);
        }
        return SecretOutcome<InfisicalNativeList<InfisicalLeaseObservation>>.Success(new(observations, true));
    }

    public async ValueTask<SecretOutcome<InfisicalLeaseObservation>> InspectLeaseAsync(
        InfisicalLeaseReference reference, CancellationToken cancellationToken = default)
    {
        ArgumentNullException.ThrowIfNull(reference);
        cancellationToken.ThrowIfCancellationRequested();
        if (reference.Definition.Target.Owner != this)
        {
            return SecretOutcome<InfisicalLeaseObservation>.Failure(SecretStatus.Invalid);
        }
        SecretOutcome<JsonDocument> response = await SendAsync(
            (_, _, token) => _wire.InspectLeaseAsync(reference.Id, Scope.ProjectSlug, Scope.EnvironmentSlug, Scope.Path, token),
            null, null, cancellationToken).ConfigureAwait(false);
        if (!response.IsSuccess)
        {
            return SecretOutcome<InfisicalLeaseObservation>.Failure(response.Status);
        }
        using JsonDocument document = response.Value;
        if (!Object(document.RootElement, "lease", out JsonElement lease) ||
            !Object(lease, "dynamicSecret", out JsonElement definition) ||
            !TryDefinition(definition, reference.Definition.Target, reference.Definition.Id, out _) ||
            !TryLease(lease, reference.Definition, reference, out InfisicalLeaseObservation? observation))
        {
            return SecretOutcome<InfisicalLeaseObservation>.Failure(SecretStatus.Invalid);
        }
        return SecretOutcome<InfisicalLeaseObservation>.Success(observation!);
    }

    /// <summary>
    /// Explicit issuance for the documented SQL database credential shape. Other material contracts
    /// are not guessed from the metadata's unspecified data field.
    /// </summary>
    public async ValueTask<SecretOutcome<InfisicalDatabaseLease>> AcquireDatabaseAsync(
        InfisicalDynamicDefinition definition, InfisicalDynamicMutationReceipt receipt,
        InfisicalLeaseDuration? ttl = null, CancellationToken cancellationToken = default)
    {
        ArgumentNullException.ThrowIfNull(definition);
        if (!ValidMutation(definition.Target, null, receipt, InfisicalDynamicOperation.Acquire, cancellationToken))
        {
            return SecretOutcome<InfisicalDatabaseLease>.Failure(SecretStatus.Invalid);
        }
        if (definition.Provider != InfisicalDynamicProvider.SqlDatabase)
        {
            return SecretOutcome<InfisicalDatabaseLease>.Failure(SecretStatus.ContractNotEstablished);
        }
        if (definition.MaximumTtl is { } maximum && (ttl ?? definition.DefaultTtl).Duration > maximum.Duration)
        {
            return SecretOutcome<InfisicalDatabaseLease>.Failure(SecretStatus.Invalid);
        }
        SecretOutcome<JsonDocument> response = await SendAsync(
            (content, mutation, token) => _wire.AcquireAsync(content!, mutation!, token),
            Body(writer =>
            {
                writer.WriteString("dynamicSecretName", definition.Target.Name);
                if (ttl is not null)
                {
                    writer.WriteString("ttl", ttl.Wire);
                }
            }), receipt, cancellationToken).ConfigureAwait(false);
        if (!response.IsSuccess)
        {
            return SecretOutcome<InfisicalDatabaseLease>.Failure(response.Status);
        }
        using JsonDocument document = response.Value;
        if (!Object(document.RootElement, "dynamicSecret", out JsonElement returned) ||
            !TryDefinition(returned, definition.Target, definition.Id, out InfisicalDynamicDefinition? current) ||
            current!.Provider != definition.Provider ||
            !Object(document.RootElement, "lease", out JsonElement lease) ||
            !TryLease(lease, current, null, out InfisicalLeaseObservation? observation) ||
            !Object(document.RootElement, "data", out JsonElement data) ||
            data.EnumerateObject().Count() != 2 ||
            Text(data, "DB_USERNAME") is not { } username || Text(data, "DB_PASSWORD") is not { } password ||
            observation!.ExpiresAt <= _time.GetUtcNow())
        {
            return SecretOutcome<InfisicalDatabaseLease>.Failure(SecretStatus.Unknown);
        }
        cancellationToken.ThrowIfCancellationRequested();
        receipt.Record(DispatchEvidence.Applied);
        return SecretOutcome<InfisicalDatabaseLease>.Success(new(observation, _time, username, password));
    }

    /// <summary>Explicit renewal uses returned expireAt, never a locally fabricated extension.</summary>
    public async ValueTask<SecretOutcome<InfisicalLeaseObservation>> RenewAsync(
        InfisicalDatabaseLease lease, InfisicalDynamicMutationReceipt receipt,
        InfisicalLeaseDuration? ttl = null, CancellationToken cancellationToken = default)
    {
        ArgumentNullException.ThrowIfNull(lease);
        if (!ValidMutation(null, lease.Reference, receipt, InfisicalDynamicOperation.Renew, cancellationToken))
        {
            return SecretOutcome<InfisicalLeaseObservation>.Failure(SecretStatus.Invalid);
        }
        if (lease.State == InfisicalLeaseLocalState.Expired)
        {
            return SecretOutcome<InfisicalLeaseObservation>.Failure(SecretStatus.Expired);
        }
        if (!lease.BeginMutation(true))
        {
            return SecretOutcome<InfisicalLeaseObservation>.Failure(SecretStatus.Conflict);
        }
        InfisicalLeaseObservation? observed = null;
        try
        {
            SecretOutcome<InfisicalLeaseObservation> result =
                await RenewObservedAsync(lease.Observation, receipt, ttl, cancellationToken).ConfigureAwait(false);
            observed = result.IsSuccess ? result.Value : null;
            return result;
        }
        finally
        {
            lease.FinishMutation(receipt, observed, false);
        }
    }

    /// <summary>Metadata-only renewal for any admitted definition; never acquires or returns credentials.</summary>
    public ValueTask<SecretOutcome<InfisicalLeaseObservation>> RenewLeaseAsync(
        InfisicalLeaseObservation previous, InfisicalDynamicMutationReceipt receipt,
        InfisicalLeaseDuration? ttl = null, CancellationToken cancellationToken = default)
    {
        ArgumentNullException.ThrowIfNull(previous);
        return previous.Reference.MaterialOwner is { } owner
            ? RenewAsync(owner, receipt, ttl, cancellationToken)
            : RenewObservedAsync(previous, receipt, ttl, cancellationToken);
    }

    private async ValueTask<SecretOutcome<InfisicalLeaseObservation>> RenewObservedAsync(
        InfisicalLeaseObservation previous, InfisicalDynamicMutationReceipt receipt,
        InfisicalLeaseDuration? ttl, CancellationToken cancellationToken)
    {
        ArgumentNullException.ThrowIfNull(previous);
        if (!ValidMutation(null, previous.Reference, receipt, InfisicalDynamicOperation.Renew, cancellationToken))
        {
            return SecretOutcome<InfisicalLeaseObservation>.Failure(SecretStatus.Invalid);
        }
        if (previous.ExpiresAt <= _time.GetUtcNow())
        {
            return SecretOutcome<InfisicalLeaseObservation>.Failure(SecretStatus.Expired);
        }
        SecretOutcome<JsonDocument> response = await SendAsync(
            (content, mutation, token) => _wire.RenewAsync(previous.Reference.Id, content!, mutation!, token),
            Body(writer =>
            {
                if (ttl is not null)
                {
                    writer.WriteString("ttl", ttl.Wire);
                }
            }), receipt, cancellationToken).ConfigureAwait(false);
        if (!response.IsSuccess)
        {
            return SecretOutcome<InfisicalLeaseObservation>.Failure(response.Status);
        }
        using JsonDocument document = response.Value;
        if (!Object(document.RootElement, "lease", out JsonElement returned) ||
            !TryLease(returned, previous.Reference.Definition, previous.Reference, out InfisicalLeaseObservation? observation) ||
            observation!.CreatedAt != previous.CreatedAt || observation.ExpiresAt <= _time.GetUtcNow() ||
            observation.Version < previous.Version)
        {
            return SecretOutcome<InfisicalLeaseObservation>.Failure(SecretStatus.Unknown);
        }
        cancellationToken.ThrowIfCancellationRequested();
        receipt.Record(DispatchEvidence.Applied);
        return SecretOutcome<InfisicalLeaseObservation>.Success(observation);
    }

    /// <summary>Remote cleanup is explicit; force removes the record without proving external revocation.</summary>
    public async ValueTask<SecretOutcome<InfisicalDynamicDeletion>> RevokeAsync(
        InfisicalDatabaseLease lease, InfisicalDynamicMutationReceipt receipt,
        bool forceRecordRemoval = false, CancellationToken cancellationToken = default)
    {
        ArgumentNullException.ThrowIfNull(lease);
        if (!ValidMutation(null, lease.Reference, receipt, InfisicalDynamicOperation.Revoke, cancellationToken))
        {
            return SecretOutcome<InfisicalDynamicDeletion>.Failure(SecretStatus.Invalid);
        }
        if (!lease.BeginMutation(false))
        {
            return SecretOutcome<InfisicalDynamicDeletion>.Failure(SecretStatus.Conflict);
        }
        try
        {
            return await RevokeReferenceAsync(lease.Reference, receipt, forceRecordRemoval, cancellationToken).ConfigureAwait(false);
        }
        finally
        {
            lease.FinishMutation(receipt, null, true);
        }
    }

    /// <summary>Explicit cleanup of an inspected or retained reference, including after local material disposal.</summary>
    public ValueTask<SecretOutcome<InfisicalDynamicDeletion>> RevokeLeaseAsync(
        InfisicalLeaseReference reference, InfisicalDynamicMutationReceipt receipt,
        bool forceRecordRemoval = false, CancellationToken cancellationToken = default)
    {
        ArgumentNullException.ThrowIfNull(reference);
        return reference.MaterialOwner is { } owner
            ? RevokeAsync(owner, receipt, forceRecordRemoval, cancellationToken)
            : RevokeReferenceAsync(reference, receipt, forceRecordRemoval, cancellationToken);
    }

    private async ValueTask<SecretOutcome<InfisicalDynamicDeletion>> RevokeReferenceAsync(
        InfisicalLeaseReference reference, InfisicalDynamicMutationReceipt receipt,
        bool forceRecordRemoval, CancellationToken cancellationToken)
    {
        ArgumentNullException.ThrowIfNull(reference);
        if (!ValidMutation(null, reference, receipt, InfisicalDynamicOperation.Revoke, cancellationToken))
        {
            return SecretOutcome<InfisicalDynamicDeletion>.Failure(SecretStatus.Invalid);
        }
        SecretOutcome<JsonDocument> response = await SendAsync(
            (content, mutation, token) => _wire.RevokeAsync(reference.Id, content!, mutation!, token),
            Body(writer => writer.WriteBoolean("isForced", forceRecordRemoval)), receipt,
            cancellationToken).ConfigureAwait(false);
        if (!response.IsSuccess)
        {
            return SecretOutcome<InfisicalDynamicDeletion>.Failure(response.Status);
        }
        using JsonDocument document = response.Value;
        if (!Object(document.RootElement, "lease", out JsonElement returned) ||
            !TryLease(returned, reference.Definition, reference, out InfisicalLeaseObservation? observation))
        {
            return SecretOutcome<InfisicalDynamicDeletion>.Failure(SecretStatus.Unknown);
        }
        cancellationToken.ThrowIfCancellationRequested();
        receipt.Record(DispatchEvidence.Applied);
        return SecretOutcome<InfisicalDynamicDeletion>.Success(new(forceRecordRemoval, observation!.NativeStatus));
    }

    private bool ValidMutation(InfisicalDynamicTarget? target, InfisicalLeaseReference? lease,
        InfisicalDynamicMutationReceipt receipt, InfisicalDynamicOperation operation, CancellationToken token)
    {
        ArgumentNullException.ThrowIfNull(receipt);
        token.ThrowIfCancellationRequested();
        return (target?.Owner ?? lease?.Definition.Target.Owner) == this && receipt.Matches(target, lease, operation);
    }

    private SecretOutcome<InfisicalDynamicDefinition> DefinitionResult(SecretOutcome<JsonDocument> response,
        InfisicalDynamicTarget target, Guid? expectedId, InfisicalDynamicMutationReceipt? receipt,
        CancellationToken token, InfisicalDynamicProvider? expectedProvider = null)
    {
        if (!response.IsSuccess)
        {
            return SecretOutcome<InfisicalDynamicDefinition>.Failure(response.Status);
        }
        using JsonDocument document = response.Value;
        if (!Object(document.RootElement, "dynamicSecret", out JsonElement returned) ||
            !TryDefinition(returned, target, expectedId, out InfisicalDynamicDefinition? definition) ||
            (expectedProvider is not null && definition!.Provider != expectedProvider))
        {
            return SecretOutcome<InfisicalDynamicDefinition>.Failure(receipt is null ? SecretStatus.Invalid : SecretStatus.Unknown);
        }
        token.ThrowIfCancellationRequested();
        receipt?.Record(DispatchEvidence.Applied);
        return SecretOutcome<InfisicalDynamicDefinition>.Success(definition!);
    }

    private bool TryDefinition(JsonElement element, InfisicalDynamicTarget target, Guid? expectedId,
        out InfisicalDynamicDefinition? definition)
    {
        definition = null;
        if (Text(element, "name") != target.Name || !GuidField(element, "folderId", out Guid folder) ||
            folder != Scope.FolderId || !GuidField(element, "id", out Guid id) || (expectedId is not null && expectedId != id) ||
            InfisicalDynamicProfile.ProviderFor(Text(element, "type")) is not { } provider ||
            InfisicalLeaseDuration.Parse(Text(element, "defaultTTL")) is not { } ttl ||
            !Number(element, "version", out decimal version) || !OptionalText(element, "maxTTL") ||
            !OptionalText(element, "status") ||
            !Date(element, "createdAt", out _) || !Date(element, "updatedAt", out _))
        {
            return false;
        }
        string? maximum = Text(element, "maxTTL");
        InfisicalLeaseDuration? max = InfisicalLeaseDuration.Parse(maximum);
        if ((maximum is not null && max is null) || max?.Duration < ttl.Duration)
        {
            return false;
        }
        definition = new(target, id, provider, ttl, max, version, Text(element, "status"));
        return true;
    }

    private static bool TryLease(JsonElement element, InfisicalDynamicDefinition definition,
        InfisicalLeaseReference? expected, out InfisicalLeaseObservation? observation)
    {
        observation = null;
        if (!GuidField(element, "id", out Guid id) || (expected is not null && expected.Id != id) ||
            !GuidField(element, "dynamicSecretId", out Guid definitionId) || definitionId != definition.Id ||
            !Date(element, "createdAt", out DateTimeOffset created) ||
            !Date(element, "expireAt", out DateTimeOffset expires) || expires <= created ||
            !Date(element, "updatedAt", out _) || !Number(element, "version", out decimal version) ||
            !OptionalText(element, "status") ||
            Text(element, "externalEntityId") is null ||
            (definition.MaximumTtl is { } max && expires - created > max.Duration))
        {
            return false;
        }
        observation = new(expected ?? new(definition, id), created, expires, version, Text(element, "status"));
        return true;
    }

    private byte[] Body(Action<Utf8JsonWriter> fields)
    {
        using var stream = new MemoryStream();
        try
        {
            using (var writer = new Utf8JsonWriter(stream))
            {
                writer.WriteStartObject();
                writer.WriteString("projectSlug", Scope.ProjectSlug);
                writer.WriteString("environmentSlug", Scope.EnvironmentSlug);
                writer.WriteString("path", Scope.Path);
                fields(writer);
                writer.WriteEndObject();
            }
            if (stream.Length > _byteLimit)
            {
                throw new ArgumentException("Native request exceeds the byte budget.");
            }
            return stream.ToArray();
        }
        finally
        {
            if (stream.TryGetBuffer(out ArraySegment<byte> bytes))
            {
                bytes.AsSpan().Clear();
            }
        }
    }

    private async ValueTask<SecretOutcome<JsonDocument>> SendAsync(
        Func<HttpContent?, InfisicalDynamicMutationReceipt?, CancellationToken, Task<HttpRequestMessage>> operation,
        byte[]? payload, InfisicalDynamicMutationReceipt? receipt, CancellationToken token)
    {
        try
        {
            token.ThrowIfCancellationRequested();
            lock (_gate)
            {
                ObjectDisposedException.ThrowIf(_disposed, this);
                _active++;
            }
            try
            {
                using var linked = CancellationTokenSource.CreateLinkedTokenSource(token, _shutdown.Token);
                using ByteArrayContent? content = payload is null ? null : new ByteArrayContent(payload);
                if (payload is not null)
                {
                    content!.Headers.ContentType = new MediaTypeHeaderValue("application/json");
                }
                linked.Token.ThrowIfCancellationRequested();
                using HttpRequestMessage request = await operation(content, receipt, linked.Token).ConfigureAwait(false);
                _binding.BindRequest(request);
                SecretOutcome<InfisicalAccessToken> supplied =
                    await _tokens.GetTokenAsync(linked.Token).ConfigureAwait(false);
                if (!supplied.IsSuccess)
                {
                    linked.Token.ThrowIfCancellationRequested();
                    return Failure(supplied.Status, receipt);
                }
                using InfisicalAccessToken access = supplied.Value;
                linked.Token.ThrowIfCancellationRequested();
                if (access.ExpiresAt <= _time.GetUtcNow())
                    return Failure(SecretStatus.Expired, receipt);
                string bearer = access.Material.Reveal();
                if (bearer.Length is < 1 or > 16384 ||
                    !bearer.All(c => char.IsAsciiLetterOrDigit(c) || c is '-' or '_' or '.' or '~' or '+' or '/' or '='))
                    return Failure(SecretStatus.Invalid, receipt);
                request.Headers.Authorization = new AuthenticationHeaderValue("Bearer", bearer);
                linked.Token.ThrowIfCancellationRequested();
                if (receipt is not null && !receipt.Begin())
                    return Failure(SecretStatus.Invalid, receipt);
                using HttpResponseMessage response = await _http.SendAsync(request,
                    HttpCompletionOption.ResponseHeadersRead, linked.Token).ConfigureAwait(false);
                linked.Token.ThrowIfCancellationRequested();
                if (response.RequestMessage?.RequestUri is { } returnedUri &&
                    returnedUri != request.RequestUri)
                {
                    return Failure(SecretStatus.Invalid, receipt);
                }
                if (!response.IsSuccessStatusCode)
                {
                    SecretStatus status = (int)response.StatusCode switch
                    {
                        400 or 422 => SecretStatus.Invalid,
                        401 or 403 => SecretStatus.Denied,
                        404 => SecretStatus.Absent,
                        409 => SecretStatus.Conflict,
                        429 => SecretStatus.Throttled,
                        >= 500 => SecretStatus.Unavailable,
                        _ => SecretStatus.Invalid
                    };
                    if (receipt is not null && (int)response.StatusCode is >= 400 and < 500)
                    {
                        receipt.Record(status == SecretStatus.Conflict ? DispatchEvidence.Conflict : DispatchEvidence.Rejected);
                        return SecretOutcome<JsonDocument>.Failure(status);
                    }
                    return Failure(status, receipt);
                }
                if (response.Content.Headers.ContentLength > _byteLimit)
                {
                    return Failure(SecretStatus.Invalid, receipt);
                }
                await using Stream stream = await response.Content.ReadAsStreamAsync(linked.Token).ConfigureAwait(false);
                using var collected = new MemoryStream();
                byte[] buffer = ArrayPool<byte>.Shared.Rent(8192);
                try
                {
                    int count;
                    while ((count = await stream.ReadAsync(buffer.AsMemory(0, 8192), linked.Token).ConfigureAwait(false)) != 0)
                    {
                        if (collected.Length + count > _byteLimit)
                        {
                            return Failure(SecretStatus.Invalid, receipt);
                        }
                        collected.Write(buffer, 0, count);
                    }
                    linked.Token.ThrowIfCancellationRequested();
                    collected.Position = 0;
                    JsonDocument document = await JsonDocument.ParseAsync(collected,
                        new JsonDocumentOptions { MaxDepth = 32 }, linked.Token).ConfigureAwait(false);
                    if (!Bounded(document.RootElement))
                    {
                        document.Dispose();
                        return Failure(SecretStatus.Invalid, receipt);
                    }
                    return SecretOutcome<JsonDocument>.Success(document);
                }
                finally
                {
                    ArrayPool<byte>.Shared.Return(buffer, clearArray: true);
                    if (collected.TryGetBuffer(out ArraySegment<byte> bytes))
                    {
                        bytes.AsSpan().Clear();
                    }
                }
            }
            finally
            {
                lock (_gate)
                {
                    if (--_active == 0)
                    {
                        _drained?.TrySetResult();
                    }
                }
            }
        }
        catch (OperationCanceledException)
        {
            throw new OperationCanceledException(token);
        }
        catch (HttpRequestException)
        {
            token.ThrowIfCancellationRequested();
            return Failure(SecretStatus.Unavailable, receipt);
        }
        catch (IOException)
        {
            token.ThrowIfCancellationRequested();
            return Failure(SecretStatus.Unavailable, receipt);
        }
        catch (JsonException)
        {
            token.ThrowIfCancellationRequested();
            return Failure(SecretStatus.Invalid, receipt);
        }
        finally
        {
            if (payload is not null)
            {
                payload.AsSpan().Clear();
            }
        }
    }

    private bool Bounded(JsonElement element)
    {
        if (element.ValueKind == JsonValueKind.Object)
        {
            var names = new HashSet<string>(StringComparer.Ordinal);
            foreach (JsonProperty property in element.EnumerateObject())
            {
                if (names.Count == _maximumItems || property.Name.Length > 1024 ||
                    !names.Add(property.Name) || !Bounded(property.Value))
                {
                    return false;
                }
            }
        }
        else if (element.ValueKind == JsonValueKind.Array)
        {
            if (element.GetArrayLength() > _maximumItems)
            {
                return false;
            }
            foreach (JsonElement item in element.EnumerateArray())
            {
                if (!Bounded(item))
                {
                    return false;
                }
            }
        }
        return element.ValueKind != JsonValueKind.String || element.GetString()!.Length <= 65536;
    }

    private static SecretOutcome<JsonDocument> Failure(SecretStatus status, InfisicalDynamicMutationReceipt? receipt) =>
        SecretOutcome<JsonDocument>.Failure(receipt?.Evidence == DispatchEvidence.PossiblyDispatched ? SecretStatus.Unknown : status);
    private static string? Text(JsonElement element, string name) =>
        element.ValueKind == JsonValueKind.Object && element.TryGetProperty(name, out JsonElement field) &&
        field.ValueKind == JsonValueKind.String ? field.GetString() : null;
    private static bool OptionalText(JsonElement element, string name) =>
        !element.TryGetProperty(name, out JsonElement field) ||
        field.ValueKind is JsonValueKind.String or JsonValueKind.Null;
    private static bool Object(JsonElement element, string name, out JsonElement value)
    {
        value = default;
        return element.ValueKind == JsonValueKind.Object && element.TryGetProperty(name, out value) &&
            value.ValueKind == JsonValueKind.Object;
    }
    private static bool Array(JsonElement element, string name, out JsonElement value)
    {
        value = default;
        return element.ValueKind == JsonValueKind.Object && element.TryGetProperty(name, out value) &&
            value.ValueKind == JsonValueKind.Array;
    }
    private static bool GuidField(JsonElement element, string name, out Guid value) =>
        Guid.TryParse(Text(element, name), out value) && value != Guid.Empty;
    private static bool Date(JsonElement element, string name, out DateTimeOffset value) =>
        DateTimeOffset.TryParseExact(Text(element, name),
            ["yyyy-MM-dd'T'HH:mm:ss.FFFFFFFK", "yyyy-MM-dd'T'HH:mm:ssK"],
            CultureInfo.InvariantCulture, DateTimeStyles.None, out value);
    private static bool Number(JsonElement element, string name, out decimal value)
    {
        value = default;
        return element.ValueKind == JsonValueKind.Object && element.TryGetProperty(name, out JsonElement field) &&
            field.ValueKind == JsonValueKind.Number && field.TryGetDecimal(out value) && value >= 0;
    }
    private static bool ValidName(string? name) => !string.IsNullOrWhiteSpace(name) &&
        name.Length <= 64 && name is not ("." or "..") && !name.Any(char.IsControl);

    public ValueTask DisposeAsync()
    {
        lock (_gate)
        {
            if (_disposeTask is not null)
            {
                return new(_disposeTask);
            }
            _disposed = true;
            _drained = new(TaskCreationOptions.RunContinuationsAsynchronously);
            if (_active == 0)
            {
                _drained.SetResult();
            }
            _disposeTask = ShutdownAsync(_drained.Task);
            return new(_disposeTask);
        }
    }
    private async Task ShutdownAsync(Task drained)
    {
        await _shutdown.CancelAsync().ConfigureAwait(false);
        try
        {
            await drained.WaitAsync(_shutdownTimeout).ConfigureAwait(false);
        }
        finally
        {
            _binding.Dispose();
            _shutdown.Dispose();
        }
    }
    public override string ToString() => "[InfisicalDynamicClient]";
}
