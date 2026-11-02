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
    private OperationSupport(ManagementOperationFamily operation, ManagementSupport support, string revision,
        IEnumerable<int> statuses)
    {
        Operation = operation;
        Support = support;
        ApiRevision = revision;
        SuccessfulHttpStatuses = Array.AsReadOnly(statuses.ToArray());
    }

    /// <summary>Gets the native operation family being described.</summary>
    public ManagementOperationFamily Operation { get; }
    /// <summary>Gets the library's projection scope, not the caller's entitlement.</summary>
    public ManagementSupport Support { get; }
    /// <summary>Gets the selected native API revision.</summary>
    public string ApiRevision { get; }
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
            bool rbac = operation is >= ManagementOperationFamily.RoleAssignmentCreate and <= ManagementOperationFamily.RoleDefinitionList;
            bool notification = operation >= ManagementOperationFamily.NotificationCreateOrUpdate;
            string revision = rbac ? "2022-04-01" : notification ? "2025-02-15" :
                operation is ManagementOperationFamily.AuditQueryWorkspace or ManagementOperationFamily.AuditQueryResource
                    ? "v1" : "2026-02-01";
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
                revision, statuses);
        }).ToArray());

    /// <summary>Returns only the operation and implementation-scope categories.</summary>
    public override string ToString() => $"[OperationSupport:{Operation}:{Support}]";
}
