namespace SecretKit.AzureKeyVault.Management;

/// <summary>The projected administrative operation families described by the static support inventory.</summary>
public enum ManagementOperationFamily
{
    /// <summary>Create or replace vault configuration.</summary>
    VaultCreateOrUpdate,
    /// <summary>Recover a deleted vault.</summary>
    VaultRecover,
    /// <summary>Patch supported vault settings.</summary>
    VaultUpdate,
    /// <summary>Read vault control-plane metadata.</summary>
    VaultGet,
    /// <summary>Delete a vault.</summary>
    VaultDelete,
    /// <summary>Read deleted-vault metadata.</summary>
    VaultGetDeleted,
    /// <summary>Purge a deleted vault.</summary>
    VaultPurgeDeleted,
    /// <summary>Enumerate vaults in a resource group.</summary>
    VaultListByResourceGroup,
    /// <summary>Enumerate vaults in a subscription.</summary>
    VaultListBySubscription,
    /// <summary>Enumerate deleted vaults.</summary>
    VaultListDeleted,
    /// <summary>Observe name availability without reservation.</summary>
    VaultCheckNameAvailability,
    /// <summary>Add secret access policies.</summary>
    AccessPolicyAdd,
    /// <summary>Replace secret access policies.</summary>
    AccessPolicyReplace,
    /// <summary>Remove secret access policies.</summary>
    AccessPolicyRemove,
    /// <summary>Read private-connection metadata.</summary>
    PrivateConnectionGet,
    /// <summary>Enumerate private connections.</summary>
    PrivateConnectionList,
    /// <summary>Approve or reject a private connection.</summary>
    PrivateConnectionUpdate,
    /// <summary>Delete a private-connection record.</summary>
    PrivateConnectionDelete,
    /// <summary>Enumerate native private-link requirements.</summary>
    PrivateLinkList,
    /// <summary>Create a selected role assignment.</summary>
    RoleAssignmentCreate,
    /// <summary>Read a selected role assignment.</summary>
    RoleAssignmentGet,
    /// <summary>Delete a selected role assignment.</summary>
    RoleAssignmentDelete,
    /// <summary>Enumerate vault-scoped role assignments.</summary>
    RoleAssignmentList,
    /// <summary>Read a selected role definition.</summary>
    RoleDefinitionGet,
    /// <summary>Enumerate role-definition metadata.</summary>
    RoleDefinitionList,
    /// <summary>Run the bounded audit projection against a workspace.</summary>
    AuditQueryWorkspace,
    /// <summary>Run the bounded audit projection against a vault resource.</summary>
    AuditQueryResource,
    /// <summary>Enumerate subscriptions visible to the selected administrative identity.</summary>
    SubscriptionList,
    /// <summary>Create or replace a notification subscription.</summary>
    NotificationCreateOrUpdate,
    /// <summary>Patch a notification subscription.</summary>
    NotificationUpdate,
    /// <summary>Delete a notification subscription.</summary>
    NotificationDelete,
    /// <summary>Read notification metadata.</summary>
    NotificationGet,
    /// <summary>Enumerate notification subscriptions.</summary>
    NotificationList,
    /// <summary>Explicitly acquire protected full endpoint material.</summary>
    NotificationGetFullUrl,
    /// <summary>Explicitly acquire protected delivery attributes.</summary>
    NotificationGetDeliveryAttributes
}

/// <summary>Implementation scope of a projection, independent of provider permissions and live verification.</summary>
public enum ManagementSupport
{
    /// <summary>A bounded subset of the native operation is projected.</summary>
    BoundedNativeSubset,
    /// <summary>The native operation is not projected by this library.</summary>
    ProjectionNotImplemented
}

/// <summary>Static contract availability, not permissions, delivery or live conformance evidence.</summary>
public sealed class OperationSupport
{
    private OperationSupport(ManagementOperationFamily operation, ManagementSupport support, ArmMethodContract? contract,
        IEnumerable<int> statuses)
    {
        Operation = operation;
        Support = support;
        ApiRevision = contract?.ApiVersion;
        SuccessfulHttpStatuses = Array.AsReadOnly(statuses.ToArray());
    }

    /// <summary>Gets the native operation family being described.</summary>
    public ManagementOperationFamily Operation { get; }
    /// <summary>Gets the library's projection scope, not the caller's entitlement.</summary>
    public ManagementSupport Support { get; }
    /// <summary>Gets the SDK method's ARM API revision, or null for a non-ARM operation.</summary>
    public string? ApiRevision { get; }
    /// <summary>Gets accepted successful wire statuses; receipt classification still depends on the response.</summary>
    public IReadOnlyList<int> SuccessfulHttpStatuses { get; }
    /// <summary>Always false: static inventory does not inspect the selected identity's permissions.</summary>
    [System.Diagnostics.CodeAnalysis.SuppressMessage("Performance", "CA1822", Justification = "Unverified permission belongs to each operation's support descriptor.")]
    public bool PermissionChecked => false;
    /// <summary>Always false: contract availability is not a live-conformance record.</summary>
    [System.Diagnostics.CodeAnalysis.SuppressMessage("Performance", "CA1822", Justification = "Unverified live behavior belongs to each operation's support descriptor.")]
    public bool LiveVerified => false;

    /// <summary>Gets immutable descriptions of all projected families without performing provider calls.</summary>
    public static IReadOnlyList<OperationSupport> Inventory { get; } = Array.AsReadOnly(
        Enum.GetValues<ManagementOperationFamily>().Select(operation =>
        {
            ArmMethodContract? contract = operation switch
            {
                ManagementOperationFamily.VaultCreateOrUpdate or ManagementOperationFamily.VaultRecover => ArmMethodContracts.VaultCreateOrUpdate,
                ManagementOperationFamily.VaultUpdate => ArmMethodContracts.VaultUpdate,
                ManagementOperationFamily.VaultGet => ArmMethodContracts.VaultGet,
                ManagementOperationFamily.VaultDelete => ArmMethodContracts.VaultDelete,
                ManagementOperationFamily.VaultGetDeleted => ArmMethodContracts.VaultGetDeleted,
                ManagementOperationFamily.VaultPurgeDeleted => ArmMethodContracts.VaultPurgeDeleted,
                ManagementOperationFamily.VaultListByResourceGroup => ArmMethodContracts.VaultListByResourceGroup,
                ManagementOperationFamily.VaultListBySubscription => ArmMethodContracts.VaultListBySubscription,
                ManagementOperationFamily.VaultListDeleted => ArmMethodContracts.VaultListDeleted,
                ManagementOperationFamily.VaultCheckNameAvailability => ArmMethodContracts.VaultCheckNameAvailability,
                ManagementOperationFamily.AccessPolicyAdd or ManagementOperationFamily.AccessPolicyReplace or
                    ManagementOperationFamily.AccessPolicyRemove => ArmMethodContracts.AccessPolicyUpdate,
                ManagementOperationFamily.PrivateConnectionGet => ArmMethodContracts.PrivateConnectionGet,
                ManagementOperationFamily.PrivateConnectionList => ArmMethodContracts.PrivateConnectionList,
                ManagementOperationFamily.PrivateConnectionUpdate => ArmMethodContracts.PrivateConnectionUpdate,
                ManagementOperationFamily.PrivateConnectionDelete => ArmMethodContracts.PrivateConnectionDelete,
                ManagementOperationFamily.PrivateLinkList => ArmMethodContracts.PrivateLinkList,
                ManagementOperationFamily.RoleAssignmentCreate => ArmMethodContracts.RoleAssignmentCreate,
                ManagementOperationFamily.RoleAssignmentGet => ArmMethodContracts.RoleAssignmentGet,
                ManagementOperationFamily.RoleAssignmentDelete => ArmMethodContracts.RoleAssignmentDelete,
                ManagementOperationFamily.RoleAssignmentList => ArmMethodContracts.RoleAssignmentList,
                ManagementOperationFamily.RoleDefinitionGet => ArmMethodContracts.RoleDefinitionGet,
                ManagementOperationFamily.RoleDefinitionList => ArmMethodContracts.RoleDefinitionList,
                ManagementOperationFamily.AuditQueryWorkspace or ManagementOperationFamily.AuditQueryResource => null,
                ManagementOperationFamily.SubscriptionList => ArmMethodContracts.SubscriptionList,
                ManagementOperationFamily.NotificationCreateOrUpdate => ArmMethodContracts.NotificationCreateOrUpdate,
                ManagementOperationFamily.NotificationUpdate => ArmMethodContracts.NotificationUpdate,
                ManagementOperationFamily.NotificationDelete => ArmMethodContracts.NotificationDelete,
                ManagementOperationFamily.NotificationGet => ArmMethodContracts.NotificationGet,
                ManagementOperationFamily.NotificationList => ArmMethodContracts.NotificationList,
                ManagementOperationFamily.NotificationGetFullUrl => ArmMethodContracts.NotificationGetFullUrl,
                ManagementOperationFamily.NotificationGetDeliveryAttributes => ArmMethodContracts.NotificationGetDeliveryAttributes,
                _ => throw new InvalidOperationException("No SDK contract binding for the management operation.")
            };
            int[] statuses = operation switch
            {
                ManagementOperationFamily.VaultCreateOrUpdate or ManagementOperationFamily.VaultRecover or
                ManagementOperationFamily.VaultUpdate or ManagementOperationFamily.AccessPolicyAdd or
                ManagementOperationFamily.AccessPolicyReplace or ManagementOperationFamily.AccessPolicyRemove or
                ManagementOperationFamily.RoleAssignmentCreate => [200, 201],
                ManagementOperationFamily.VaultDelete or ManagementOperationFamily.RoleAssignmentDelete => [200, 204],
                ManagementOperationFamily.VaultPurgeDeleted => [200, 202],
                ManagementOperationFamily.PrivateConnectionGet => [200, 204],
                ManagementOperationFamily.PrivateConnectionDelete or ManagementOperationFamily.NotificationDelete => [200, 202, 204],
                ManagementOperationFamily.NotificationCreateOrUpdate or ManagementOperationFamily.NotificationUpdate => [201],
                _ => [200]
            };
            return new OperationSupport(operation,
                ManagementSupport.BoundedNativeSubset,
                contract, statuses);
        }).ToArray());

    /// <summary>Returns only the operation and implementation-scope categories.</summary>
    public override string ToString() => $"[OperationSupport:{Operation}:{Support}]";
}
