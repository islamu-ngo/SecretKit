namespace SecretKit.AzureKeyVault.Management;

public enum ManagementOperationFamily
{
    VaultCreateOrUpdate, VaultRecover, VaultUpdate, VaultGet, VaultDelete, VaultGetDeleted,
    VaultPurgeDeleted, VaultListByResourceGroup, VaultListBySubscription, VaultListDeleted,
    VaultCheckNameAvailability, AccessPolicyAdd, AccessPolicyReplace, AccessPolicyRemove,
    PrivateConnectionGet, PrivateConnectionList, PrivateConnectionUpdate, PrivateConnectionDelete,
    PrivateLinkList, RoleAssignmentCreate, RoleAssignmentGet, RoleAssignmentDelete, RoleAssignmentList,
    RoleDefinitionGet, RoleDefinitionList, AuditQueryWorkspace, AuditQueryResource,
    NotificationCreateOrUpdate, NotificationUpdate, NotificationDelete, NotificationGet, NotificationList,
    NotificationGetFullUrl, NotificationGetDeliveryAttributes
}

public enum ManagementSupport { BoundedNativeSubset, ProjectionNotImplemented }

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

    public ManagementOperationFamily Operation { get; }
    public ManagementSupport Support { get; }
    public string ApiRevision { get; }
    public IReadOnlyList<int> SuccessfulHttpStatuses { get; }
    public bool PermissionChecked => false;
    public bool LiveVerified => false;

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

    public override string ToString() => $"[OperationSupport:{Operation}:{Support}]";
}
