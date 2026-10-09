using System.Text.Json.Serialization;
using Azure;
using Azure.Core;
using Azure.ResourceManager.Authorization;
using Azure.ResourceManager.Authorization.Models;
using SecretKit.Core;

namespace SecretKit.AzureKeyVault.Management;

public sealed class RoleAssignmentScope : ManagementScope
{
    public RoleAssignmentScope(ManagementScope parent, Guid assignmentId)
    {
        if (parent is not (VaultScope or ResourceGroupScope or SubscriptionScope))
            throw new ArgumentException("Invalid role assignment scope.");
        Parent = parent;
        AssignmentId = Identifier(assignmentId);
    }

    [JsonIgnore] public ManagementScope Parent { get; }
    [JsonIgnore] public Guid AssignmentId { get; }
    internal SubscriptionScope Subscription => Parent switch
    {
        VaultScope vault => vault.ResourceGroup.Subscription,
        ResourceGroupScope group => group.Subscription,
        SubscriptionScope subscription => subscription,
        _ => throw new ArgumentException("Invalid role assignment scope.")
    };
    internal override string ResourceId =>
        $"{Parent.ResourceId}/providers/Microsoft.Authorization/roleAssignments/{AssignmentId:D}";
}

public sealed class RoleDefinitionScope(SubscriptionScope subscription, Guid definitionId) : ManagementScope
{
    [JsonIgnore]
    public SubscriptionScope Subscription { get; } =
        subscription ?? throw new ArgumentNullException(nameof(subscription));
    [JsonIgnore] public Guid DefinitionId { get; } = Identifier(definitionId);
    internal override string ResourceId =>
        $"{Subscription.ResourceId}/providers/Microsoft.Authorization/roleDefinitions/{DefinitionId:D}";
}

/// <summary>Provider-authored assignment metadata, not effective-access evidence.</summary>
public sealed class RoleAssignmentObservation
{
    internal RoleAssignmentObservation(RoleAssignmentScope scope, RoleDefinitionScope definition,
        RoleAssignmentData data)
    {
        Scope = scope;
        Definition = definition;
        PrincipalId = data.PrincipalId ?? throw new ControlledTransport.BoundaryException();
        if (PrincipalId == Guid.Empty) throw new ControlledTransport.BoundaryException();
        PrincipalType = data.PrincipalType?.ToString();
        Description = data.Description;
        Condition = data.Condition;
        ConditionVersion = data.ConditionVersion;
    }

    [JsonIgnore] public RoleAssignmentScope Scope { get; }
    [JsonIgnore] public RoleDefinitionScope Definition { get; }
    [JsonIgnore] public Guid PrincipalId { get; }
    [JsonIgnore] public string? PrincipalType { get; }
    [JsonIgnore] public string? Description { get; }
    [JsonIgnore] public string? Condition { get; }
    [JsonIgnore] public string? ConditionVersion { get; }
    public override string ToString() => "[RoleAssignmentObservation]";
}

public sealed class RolePermissionObservation
{
    internal RolePermissionObservation(RoleDefinitionPermission permission)
    {
        Actions = Array.AsReadOnly(permission.Actions.ToArray());
        NotActions = Array.AsReadOnly(permission.NotActions.ToArray());
        DataActions = Array.AsReadOnly(permission.DataActions.ToArray());
        NotDataActions = Array.AsReadOnly(permission.NotDataActions.ToArray());
    }

    [JsonIgnore] public IReadOnlyList<string> Actions { get; }
    [JsonIgnore] public IReadOnlyList<string> NotActions { get; }
    [JsonIgnore] public IReadOnlyList<string> DataActions { get; }
    [JsonIgnore] public IReadOnlyList<string> NotDataActions { get; }
    public override string ToString() => "[RolePermissionObservation]";
}

/// <summary>A role definition is not proof that a principal has its permissions.</summary>
public sealed class RoleDefinitionObservation
{
    internal RoleDefinitionObservation(RoleDefinitionScope scope, AuthorizationRoleDefinitionData data)
    {
        Scope = scope;
        Name = data.RoleName;
        Description = data.Description;
        RoleType = data.RoleType?.ToString();
        Permissions = Array.AsReadOnly(data.Permissions.Select(p => new RolePermissionObservation(p)).ToArray());
        AssignableScopes = Array.AsReadOnly(data.AssignableScopes.ToArray());
    }

    [JsonIgnore] public RoleDefinitionScope Scope { get; }
    [JsonIgnore] public string? Name { get; }
    [JsonIgnore] public string? Description { get; }
    [JsonIgnore] public string? RoleType { get; }
    [JsonIgnore] public IReadOnlyList<RolePermissionObservation> Permissions { get; }
    [JsonIgnore] public IReadOnlyList<string> AssignableScopes { get; }
    public override string ToString() => "[RoleDefinitionObservation]";
}

public sealed partial class VaultAdministration
{
    private const string RoleRevision = "2022-04-01";

    public ValueTask<SecretOutcome<RoleAssignmentObservation>> GetRoleAssignmentAsync(RoleAssignmentScope scope,
        CancellationToken cancellationToken = default)
    {
        ArgumentNullException.ThrowIfNull(scope);
        return Read(scope.ResourceId, async (client, token) => ObserveRoleAssignment(scope,
            (await client.GetRoleAssignmentResource(new ResourceIdentifier(scope.ResourceId))
                .GetAsync(cancellationToken: token).ConfigureAwait(false)).Value.Data),
            cancellationToken, revision: RoleRevision);
    }

    public ValueTask<ManagementInventory<RoleAssignmentObservation>> ListRoleAssignmentsAsync(VaultScope scope,
        CollectionLimits limits, CancellationToken cancellationToken = default)
    {
        ArgumentNullException.ThrowIfNull(scope);
        return Collect($"{scope.ResourceId}/providers/Microsoft.Authorization/roleAssignments", limits,
            (client, token) => client.GetRoleAssignments(new ResourceIdentifier(scope.ResourceId))
                .GetAllAsync(filter: "atScope()", cancellationToken: token),
            resource =>
            {
                if (!Guid.TryParse(resource.Id.Name, out var id)) throw new ControlledTransport.BoundaryException();
                // atScope() includes assignments on these selected native ancestors, not only the vault.
                ManagementScope parent = new ManagementScope[]
                    { scope, scope.ResourceGroup, scope.ResourceGroup.Subscription }
                    .FirstOrDefault(candidate => string.Equals(resource.Data.Scope, candidate.ResourceId,
                        StringComparison.OrdinalIgnoreCase)) ?? throw new ControlledTransport.BoundaryException();
                return ObserveRoleAssignment(new RoleAssignmentScope(parent, id), resource.Data);
            }, cancellationToken, RoleRevision);
    }

    public ValueTask<SecretOutcome<RoleDefinitionObservation>> GetRoleDefinitionAsync(RoleDefinitionScope scope,
        CancellationToken cancellationToken = default)
    {
        ArgumentNullException.ThrowIfNull(scope);
        return Read(scope.ResourceId, async (client, token) => ObserveRoleDefinition(scope,
            (await client.GetAuthorizationRoleDefinitionResource(new ResourceIdentifier(scope.ResourceId))
                .GetAsync(token).ConfigureAwait(false)).Value.Data), cancellationToken, revision: RoleRevision);
    }

    public ValueTask<ManagementInventory<RoleDefinitionObservation>> ListRoleDefinitionsAsync(SubscriptionScope scope,
        CollectionLimits limits, CancellationToken cancellationToken = default)
    {
        ArgumentNullException.ThrowIfNull(scope);
        return Collect($"{scope.ResourceId}/providers/Microsoft.Authorization/roleDefinitions", limits,
            (client, token) => client.GetAuthorizationRoleDefinitions(new ResourceIdentifier(scope.ResourceId))
                .GetAllAsync(cancellationToken: token),
            resource =>
            {
                if (!Guid.TryParse(resource.Id.Name, out var id)) throw new ControlledTransport.BoundaryException();
                return ObserveRoleDefinition(new RoleDefinitionScope(scope, id), resource.Data);
            }, cancellationToken, RoleRevision);
    }

    /// <summary>Explicit create/update; never a conditional create or an effective-access claim.</summary>
    public ValueTask<SecretOutcome<RoleAssignmentObservation>> CreateRoleAssignmentAsync(RoleAssignmentScope scope,
        RoleDefinitionScope definition, Guid principalId, ManagementReceipt receipt,
        CancellationToken cancellationToken = default)
    {
        ArgumentNullException.ThrowIfNull(scope);
        ArgumentNullException.ThrowIfNull(definition);
        if (scope.Parent is not VaultScope vault || principalId == Guid.Empty ||
            definition.Subscription.SubscriptionId != vault.ResourceGroup.Subscription.SubscriptionId)
        {
            return ValueTask.FromResult(SecretOutcome<RoleAssignmentObservation>.Failure(SecretStatus.Invalid));
        }

        return Mutate(scope, ManagementMutation.CreateRoleAssignment, receipt, scope.ResourceId, RequestMethod.Put,
            [200, 201], async (client, _, token) =>
            {
                var operation = await client.GetRoleAssignments(new ResourceIdentifier(vault.ResourceId))
                    .CreateOrUpdateAsync(WaitUntil.Started, scope.AssignmentId.ToString("D"),
                        new RoleAssignmentCreateOrUpdateContent(new ResourceIdentifier(definition.ResourceId), principalId),
                        token).ConfigureAwait(false);
                if (!operation.HasValue) throw new ControlledTransport.BoundaryException();
                var value = ObserveRoleAssignment(scope, operation.Value.Data);
                if (value.PrincipalId != principalId || !Same(operation.Value.Data.RoleDefinitionId, definition.ResourceId))
                    throw new ControlledTransport.BoundaryException();
                return value;
            }, cancellationToken, RoleRevision);
    }

    public ValueTask<SecretOutcome<ManagementOperation>> DeleteRoleAssignmentAsync(RoleAssignmentScope scope,
        ManagementReceipt receipt, CancellationToken cancellationToken = default)
    {
        ArgumentNullException.ThrowIfNull(scope);
        if (scope.Parent is not VaultScope)
            return ValueTask.FromResult(SecretOutcome<ManagementOperation>.Failure(SecretStatus.Invalid));
        return Mutate(scope, ManagementMutation.DeleteRoleAssignment, receipt, scope.ResourceId, RequestMethod.Delete,
            [200, 204], async (client, transport, token) =>
            {
                try
                {
                    return ManagementOperation.From(
                        await client.GetRoleAssignmentResource(new ResourceIdentifier(scope.ResourceId))
                            .DeleteAsync(WaitUntil.Started, cancellationToken: token).ConfigureAwait(false),
                        transport, _timeout, _time);
                }
                catch (NullReferenceException) when (transport.LastStatus == 204)
                {
                    // The pinned SDK dereferences the absent resource model on native 204.
                    // Only the validated, observed terminal response closes the caller's receipt.
                    return ManagementOperation.Completed(transport, _timeout, _time);
                }
            }, cancellationToken, RoleRevision);
    }

    private static RoleAssignmentObservation ObserveRoleAssignment(RoleAssignmentScope scope, RoleAssignmentData data)
    {
        if (!Same(data.Id, scope.ResourceId) ||
            !string.Equals(data.Scope, scope.Parent.ResourceId, StringComparison.OrdinalIgnoreCase) ||
            data.RoleDefinitionId is null ||
            !Guid.TryParse(data.RoleDefinitionId.Name, out var id))
            throw new ControlledTransport.BoundaryException();
        var definition = new RoleDefinitionScope(scope.Subscription, id);
        if (!Same(data.RoleDefinitionId, definition.ResourceId)) throw new ControlledTransport.BoundaryException();
        return new(scope, definition, data);
    }

    private static RoleDefinitionObservation ObserveRoleDefinition(RoleDefinitionScope scope,
        AuthorizationRoleDefinitionData data)
    {
        if (!Same(data.Id, scope.ResourceId)) throw new ControlledTransport.BoundaryException();
        return new(scope, data);
    }
}
