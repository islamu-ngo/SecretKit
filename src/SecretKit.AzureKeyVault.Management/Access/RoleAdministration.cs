using System.Text.Json.Serialization;
using Azure;
using Azure.Core;
using Azure.ResourceManager.Authorization;
using Azure.ResourceManager.Authorization.Models;
using SecretKit.Core;

namespace SecretKit.AzureKeyVault.Management;

/// <summary>A named role assignment at a vault, resource group or subscription; mutations support vault scope only.</summary>
public sealed class RoleAssignmentScope : ManagementScope
{
    /// <summary>Validates the parent scope and assignment identifier without checking access.</summary>
    /// <param name="parent">The selected vault, resource group or subscription.</param>
    /// <param name="assignmentId">The nonempty native assignment identifier.</param>
    /// <exception cref="ArgumentException">The scope kind or identifier is invalid.</exception>
    public RoleAssignmentScope(ManagementScope parent, Guid assignmentId)
    {
        if (parent is not (VaultScope or ResourceGroupScope or SubscriptionScope))
            throw new ArgumentException("Invalid role assignment scope.");
        Parent = parent;
        AssignmentId = Identifier(assignmentId);
    }

    /// <summary>Gets the protected native parent scope.</summary>
    [JsonIgnore] public ManagementScope Parent { get; }
    /// <summary>Gets the protected assignment identifier.</summary>
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

/// <summary>A role definition addressed within an explicitly selected subscription.</summary>
/// <param name="subscription">The parent subscription coordinates.</param>
/// <param name="definitionId">The nonempty role definition identifier.</param>
public sealed class RoleDefinitionScope(SubscriptionScope subscription, Guid definitionId) : ManagementScope
{
    /// <summary>Gets the protected subscription scope.</summary>
    [JsonIgnore]
    public SubscriptionScope Subscription { get; } =
        subscription ?? throw new ArgumentNullException(nameof(subscription));
    /// <summary>Gets the protected native definition identifier.</summary>
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

    /// <summary>Gets the protected observed assignment scope.</summary>
    [JsonIgnore] public RoleAssignmentScope Scope { get; }
    /// <summary>Gets the validated referenced role definition coordinates.</summary>
    [JsonIgnore] public RoleDefinitionScope Definition { get; }
    /// <summary>Gets the native principal identifier, not a credential or permission proof.</summary>
    [JsonIgnore] public Guid PrincipalId { get; }
    /// <summary>Gets the reported native principal type, if supplied.</summary>
    [JsonIgnore] public string? PrincipalType { get; }
    /// <summary>Gets protected descriptive metadata, if supplied.</summary>
    [JsonIgnore] public string? Description { get; }
    /// <summary>Gets the native condition text without interpreting or executing it.</summary>
    [JsonIgnore] public string? Condition { get; }
    /// <summary>Gets the reported native condition version, if supplied.</summary>
    [JsonIgnore] public string? ConditionVersion { get; }
    /// <summary>Returns a marker without identity, condition or scope contents.</summary>
    public override string ToString() => "[RoleAssignmentObservation]";
}

/// <summary>Copied native permission expressions, not an effective-access evaluation.</summary>
public sealed class RolePermissionObservation
{
    internal RolePermissionObservation(RoleDefinitionPermission permission)
    {
        Actions = Array.AsReadOnly(permission.Actions.ToArray());
        NotActions = Array.AsReadOnly(permission.NotActions.ToArray());
        DataActions = Array.AsReadOnly(permission.DataActions.ToArray());
        NotDataActions = Array.AsReadOnly(permission.NotDataActions.ToArray());
    }

    /// <summary>Gets copied control-plane action expressions.</summary>
    [JsonIgnore] public IReadOnlyList<string> Actions { get; }
    /// <summary>Gets control-plane exclusions from the role's action expressions.</summary>
    [JsonIgnore] public IReadOnlyList<string> NotActions { get; }
    /// <summary>Gets copied data-plane action expressions.</summary>
    [JsonIgnore] public IReadOnlyList<string> DataActions { get; }
    /// <summary>Gets data-plane exclusions from this role, not global denial rules.</summary>
    [JsonIgnore] public IReadOnlyList<string> NotDataActions { get; }
    /// <summary>Returns a marker without permission expressions.</summary>
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

    /// <summary>Gets the protected definition coordinates.</summary>
    [JsonIgnore] public RoleDefinitionScope Scope { get; }
    /// <summary>Gets the native role name, if supplied.</summary>
    [JsonIgnore] public string? Name { get; }
    /// <summary>Gets protected native description text, if supplied.</summary>
    [JsonIgnore] public string? Description { get; }
    /// <summary>Gets the native role category, if supplied.</summary>
    [JsonIgnore] public string? RoleType { get; }
    /// <summary>Gets copied native permission groups without evaluating their effective permissions.</summary>
    [JsonIgnore] public IReadOnlyList<RolePermissionObservation> Permissions { get; }
    /// <summary>Gets copied native assignable scope expressions, not a grant to create assignments.</summary>
    [JsonIgnore] public IReadOnlyList<string> AssignableScopes { get; }
    /// <summary>Returns a marker without role contents.</summary>
    public override string ToString() => "[RoleDefinitionObservation]";
}

public sealed partial class VaultAdministration
{
    private const string RoleRevision = "2022-04-01";

    /// <summary>Reads one assignment and validates its parent, definition and principal coordinates.</summary>
    /// <param name="scope">The selected assignment at a supported parent scope.</param>
    /// <param name="cancellationToken">Cancels this read and propagates caller cancellation.</param>
    /// <returns>Native assignment metadata, not effective access, or a bounded failure.</returns>
    /// <exception cref="ArgumentNullException">The scope is null.</exception>
    /// <exception cref="OperationCanceledException">Caller cancellation was observed.</exception>
    public ValueTask<SecretOutcome<RoleAssignmentObservation>> GetRoleAssignmentAsync(RoleAssignmentScope scope,
        CancellationToken cancellationToken = default)
    {
        ArgumentNullException.ThrowIfNull(scope);
        return Read(scope.ResourceId, async (client, token) => ObserveRoleAssignment(scope,
            (await client.GetRoleAssignmentResource(new ResourceIdentifier(scope.ResourceId))
                .GetAsync(cancellationToken: token).ConfigureAwait(false)).Value.Data),
            cancellationToken, revision: RoleRevision);
    }

    /// <summary>Collects bounded at-scope assignments, including the selected vault's resource-group/subscription ancestors.</summary>
    /// <param name="scope">The vault whose native at-scope assignments are requested.</param>
    /// <param name="limits">Local collection budgets.</param>
    /// <param name="cancellationToken">Cancels enumeration and propagates caller cancellation.</param>
    /// <returns>Copied assignments with explicit completeness, not an effective-access evaluation.</returns>
    /// <exception cref="ArgumentNullException">The scope or limits is null.</exception>
    /// <exception cref="OperationCanceledException">Caller cancellation was observed.</exception>
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

    /// <summary>Reads a native role definition without evaluating or granting its permissions.</summary>
    /// <param name="scope">The selected subscription-bound definition.</param>
    /// <param name="cancellationToken">Cancels the read and propagates caller cancellation.</param>
    /// <returns>Copied definition metadata, or a bounded failure.</returns>
    /// <exception cref="ArgumentNullException">The scope is null.</exception>
    /// <exception cref="OperationCanceledException">Caller cancellation was observed.</exception>
    public ValueTask<SecretOutcome<RoleDefinitionObservation>> GetRoleDefinitionAsync(RoleDefinitionScope scope,
        CancellationToken cancellationToken = default)
    {
        ArgumentNullException.ThrowIfNull(scope);
        return Read(scope.ResourceId, async (client, token) => ObserveRoleDefinition(scope,
            (await client.GetAuthorizationRoleDefinitionResource(new ResourceIdentifier(scope.ResourceId))
                .GetAsync(token).ConfigureAwait(false)).Value.Data), cancellationToken, revision: RoleRevision);
    }

    /// <summary>Collects bounded native role definitions within a subscription.</summary>
    /// <param name="scope">The selected subscription.</param>
    /// <param name="limits">Local collection budgets.</param>
    /// <param name="cancellationToken">Cancels enumeration and propagates caller cancellation.</param>
    /// <returns>Copied definitions and explicit completeness; no principal permissions are established.</returns>
    /// <exception cref="ArgumentNullException">The scope or limits is null.</exception>
    /// <exception cref="OperationCanceledException">Caller cancellation was observed.</exception>
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
    /// <param name="scope">A vault-scoped assignment with an explicitly selected identifier.</param>
    /// <param name="definition">A role definition in the same subscription.</param>
    /// <param name="principalId">The nonempty intended principal identifier.</param>
    /// <param name="receipt">Unused client-prepared evidence bound to this exact scope and CreateRoleAssignment.</param>
    /// <param name="cancellationToken">Cancels locally; retained receipt evidence survives uncertainty.</param>
    /// <returns>Validated native assignment metadata, or a bounded failure without replay.</returns>
    /// <exception cref="ArgumentNullException">A required scope, definition or receipt is null.</exception>
    /// <exception cref="OperationCanceledException">Caller cancellation was observed; inspect the receipt.</exception>
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

    /// <summary>Deletes one vault-scoped assignment without retrying or assuming immediate effective-access revocation.</summary>
    /// <param name="scope">The exact vault-scoped assignment.</param>
    /// <param name="receipt">Unused client-prepared evidence for this scope and DeleteRoleAssignment.</param>
    /// <param name="cancellationToken">Cancels locally without undoing a dispatched deletion.</param>
    /// <returns>A local operation handle, or a bounded failure; status checks are explicit.</returns>
    /// <exception cref="ArgumentNullException">The scope or receipt is null.</exception>
    /// <exception cref="OperationCanceledException">Caller cancellation was observed; inspect the receipt.</exception>
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
