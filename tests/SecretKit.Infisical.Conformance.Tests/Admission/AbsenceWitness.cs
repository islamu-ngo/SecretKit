using SecretKit.Core;
using SecretKit.Infisical.Management;
using SecretKit.TestFixtures;

namespace SecretKit.Infisical.Conformance.Tests;

internal sealed class AbsenceTarget<TItem>
{
    private readonly string? id;
    private readonly string? name;
    private readonly Func<TItem, string?> itemId;
    private readonly Func<TItem, string?> itemName;

    internal AbsenceTarget(string? id, string? name, Func<TItem, string?> itemId, Func<TItem, string?> itemName)
    {
        if (string.IsNullOrEmpty(id) && string.IsNullOrEmpty(name)) throw new ArgumentException("absence-target");
        (this.id, this.name, this.itemId, this.itemName) = (NullIfEmpty(id), NullIfEmpty(name), itemId, itemName);
    }

    internal bool Identifies(TItem item) =>
        id is not null && string.Equals(itemId(item), id, StringComparison.Ordinal) ||
        name is not null && string.Equals(itemName(item), name, StringComparison.Ordinal);

    private static string? NullIfEmpty(string? value) => string.IsNullOrEmpty(value) ? null : value;
}

/// <summary>
/// The only harness witness of Infisical resource absence. Infisical reports a resource 404 and a
/// visible-inventory omission as <see cref="SecretStatus.Unknown"/> with
/// <see cref="SecretFailureReason.NotFoundOrInaccessible"/>, so neither alone proves absence. Absence
/// holds only when the full-visibility observer's exact read is concealed in exactly that way (not
/// Denied, not a transport or other failure) AND the same observer's complete inventory of the exact
/// parent scope omits the resource by ID and by name or slug.
/// </summary>
internal static class AbsenceWitness
{
    internal static bool Concealed<T>(SecretOutcome<T> exact) where T : notnull =>
        exact is { Status: SecretStatus.Unknown, Reason: SecretFailureReason.NotFoundOrInaccessible };

    internal static bool Omits<TItem>(SecretOutcome<ManagementPage<TItem>> inventory, AbsenceTarget<TItem> target)
        where TItem : notnull =>
        inventory.IsSuccess && Omits(inventory.Value.IsComplete, inventory.Value.Items, target);

    internal static bool Omits<TItem>(SecretOutcome<InfisicalNativeList<TItem>> inventory, AbsenceTarget<TItem> target)
        where TItem : notnull =>
        inventory.IsSuccess && Omits(inventory.Value.IsComplete, inventory.Value.Items, target);


    internal static bool Omits(SecretOutcome<SqlSecretRotationList> inventory, AbsenceTarget<SqlSecretRotationSummary> target) =>
        inventory.IsSuccess && Omits(inventory.Value.IsComplete, inventory.Value.Items, target);

    internal static bool Holds<TRead, TItem>(SecretOutcome<TRead> exact, SecretOutcome<ManagementPage<TItem>> inventory,
        AbsenceTarget<TItem> target) where TRead : notnull where TItem : notnull =>
        Concealed(exact) && Omits(inventory, target);

    internal static bool Holds<TRead, TItem>(SecretOutcome<TRead> exact, SecretOutcome<InfisicalNativeList<TItem>> inventory,
        AbsenceTarget<TItem> target) where TRead : notnull where TItem : notnull =>
        Concealed(exact) && Omits(inventory, target);

    // The proxy endpoint returns an unpaged, bounded services array under its native project slug.
    // Its closed response contract rejects unadvertised paging fields; the selected slug must also match.
    internal static bool Holds(SecretOutcome<ProxiedServiceSummary> exact, SecretOutcome<ProxiedServiceList> inventory,
        string projectSlug, AbsenceTarget<ProxiedServiceSummary> target) =>
        Concealed(exact) && inventory.IsSuccess && inventory.Value.ProjectSlug == projectSlug &&
        !inventory.Value.Services.Any(target.Identifies);

    // A secret is absent only when the observer's exact read is concealed and the observer's complete
    // native inventory of the exact folder (with imports when the read includes them) lists no such key.
    internal static async ValueTask<bool> SecretAbsentAsync(InfisicalClient observer, SecretOutcome<SecretRead> exact,
        InfisicalSecretAddress address, CancellationToken token)
    {
        if (!Concealed(exact)) return false;
        SecretOutcome<InfisicalInventory> inventory = await observer.InspectNativeAsync(new InfisicalInventorySelection(
            observer.Authority, address.ProjectId, address.Environment, address.Folder,
            includeImports: address.IncludeImports), token);
        return inventory.IsSuccess && Omits(inventory.Value.IsComplete, inventory.Value.Entries,
            new AbsenceTarget<InfisicalInventoryEntry>(null, address.Key, _ => null, e => e.Key));
    }

    // A dynamic definition is absent only when the observer's exact inspection is concealed and the
    // observer's complete definition inventory of the same scope lists no definition by that name or ID.
    internal static async ValueTask<bool> DefinitionAbsentAsync(InfisicalDynamicClient observer,
        SecretOutcome<InfisicalDynamicDefinition> exact, string name, Guid? id, CancellationToken token)
    {
        if (!Concealed(exact)) return false;
        return Omits(await observer.ListDefinitionsAsync(token), new AbsenceTarget<InfisicalDynamicDefinition>(
            id?.ToString("D"), name, d => d.Id.ToString("D"), d => d.Target.Name));
    }

    // The complete project-wide SQL rotation inventory for the selected credential profile.
    internal static ManagementRequest<SqlSecretRotationList> RotationInventory(InfisicalRotationProfile profile,
        string organizationId, string projectId) => profile switch
        {
            InfisicalRotationProfile.PostgresCredentials => PostgresSecretRotationOperations.List(organizationId, projectId),
            InfisicalRotationProfile.MysqlCredentials => MySqlSecretRotationOperations.List(organizationId, projectId),
            InfisicalRotationProfile.MssqlCredentials => MsSqlSecretRotationOperations.List(organizationId, projectId),
            _ => throw new NativeCaseFailureException("missing-input")
        };

    internal static AbsenceTarget<SqlSecretRotationSummary> Rotation(string? id, string? name) =>
        new(id, name, rotation => rotation.Id, rotation => rotation.Name);

    internal static bool Holds<TRead>(SecretOutcome<TRead> exact, SecretOutcome<SqlSecretRotationList> inventory,
        AbsenceTarget<SqlSecretRotationSummary> target) where TRead : notnull =>
        Concealed(exact) && Omits(inventory, target);

    // Infisical answers GET of an auth method that is not attached to an identity with HTTP 400, not 404.
    internal static bool Unattached<T>(SecretOutcome<T> exact, SecretOutcome<IdentitySummary> identity, string authMethod)
        where T : notnull =>
        exact.Status == SecretStatus.Invalid && identity.IsSuccess &&
        identity.Value.AuthMethods is { IsPresent: true, IsNull: false } methods &&
        !methods.Value.Contains(authMethod, StringComparer.Ordinal);

    private static bool Omits<TItem>(bool complete, IEnumerable<TItem> items, AbsenceTarget<TItem> target) =>
        complete && !items.Any(target.Identifies);
}
