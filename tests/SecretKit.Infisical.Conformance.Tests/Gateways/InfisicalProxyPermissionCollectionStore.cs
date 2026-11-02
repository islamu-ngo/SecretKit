using System.Text.Json;

namespace SecretKit.Infisical.Conformance.Tests;

// Independent collection observer: owns its own state/history and parses complete
// committed configuration independently of the service store's fingerprints.
internal sealed class InfisicalProxyPermissionCollectionStore
{
    private readonly Dictionary<string, ProxyPermissionState> live = [];
    private readonly Dictionary<string, ProxyPermissionState> deletedServices = [];
    private readonly Dictionary<string, ProxyPermissionCredentialState> last = [];
    private readonly List<ProxyPermissionCollectionChange> history = [];
    private readonly List<ProxyPermissionRetirement> retired = [];
    internal int Count => live.Count;
    internal void Persist(ProxyPermissionRoot root, string request, string commit, string inputHash, string row,
        string organization, string project, string environment, string path, JsonElement document, int version)
    {
        string service = document.GetProperty("id").GetString()!;
        ProxyPermissionCredentialState Parse(int slot)
        {
            var c = document.GetProperty("credentials")[slot];
            var fingerprint = ProxyPermissionContract.Hash(new
            {
                Role = c.GetProperty("role").GetString(),
                SecretKey = c.GetProperty("secretKey").GetString(),
                PlaceholderKey = c.GetProperty("placeholderKey").GetString(),
                PlaceholderHash = ProxyPermissionContract.Hash(c.GetProperty("placeholderValue").GetString()),
                Surfaces = string.Join(",", c.GetProperty("substitutionSurfaces").EnumerateArray().Select(x => x.GetString())),
                DynamicSecretName = c.GetProperty("dynamicSecretName").GetString(),
                DynamicSecretField = c.GetProperty("dynamicSecretField").GetString(),
                HeaderName = c.GetProperty("headerName").GetString(),
                HeaderPrefix = c.GetProperty("headerPrefix").GetString(),
                HeaderPurpose = c.GetProperty("headerPurpose").GetString()
            });
            return new(slot, c.GetProperty("id").GetString()!, c.GetProperty("serviceId").GetString()!, fingerprint);
        }
        var next = new ProxyPermissionState(row, service, organization, project, document.GetProperty("name").GetString()!,
            document.GetProperty("hostPattern").GetString()!, environment, path, document.GetProperty("folderId").GetString()!,
            document.GetProperty("isEnabled").GetBoolean(), version, Parse(0), Parse(1));
        var previous = live.GetValueOrDefault(service);
        Advance(root, request, commit, inputHash, previous, next); live[service] = next;
        foreach (var credential in next.Credentials) last[credential.Id] = credential;
    }
    internal void Retire(ProxyPermissionRoot root, string service, string request, string commit, string inputHash)
    {
        Advance(root, request, commit, inputHash, live[service], null); deletedServices.Add(service, live[service]); live.Remove(service);
    }
    private void Advance(ProxyPermissionRoot root, string request, string commit, string inputHash, ProxyPermissionState? before, ProxyPermissionState? after)
    {
        history.Add(new(root.Id, root.Nonce, request, commit, inputHash, before, after));
        foreach (var c in before?.Credentials ?? [])
            retired.Add(new(before!.Target, before.Version, c.Slot, c.Id, c.Fingerprint, request,
                after is null ? "service-retired" : after.Credentials[c.Slot].Id == c.Id ? "retained-id" : "replaced-id"));
    }
    internal ProxyPermissionCollections Snapshot()
    {
        var active = live.Values.SelectMany(s => s.Credentials).ToArray();
        return new(live.Values.ToArray(), history.ToArray(), retired.ToArray(), active,
            last.Values.Where(c => !active.Any(a => a.Id == c.Id)).ToArray(), deletedServices.Values.ToArray());
    }
}

internal sealed partial class InfisicalProxyPermissionFixture
{
    private ProxyPermissionCollectionChange[] CollectionHistory(ProxyPermissionStep step) => CorruptHistory(collectionHistory.ToArray(), step);
    private ProxyPermissionCollectionChange[] CorruptHistory(ProxyPermissionCollectionChange[] history, ProxyPermissionStep step)
    {
        if (step != ProxyPermissionStep.Open || history.Length == 0) return history;
        var change = history[0]; var state = change.After!;
        switch (Fault)
        {
            case "allocation-duplicate": history[0] = change with { After = state with { Second = state.First with { Slot = 1 } } }; break;
            case "allocation-reordered": history[0] = change with { After = state with { First = state.Second, Second = state.First } }; break;
            case "allocation-substituted": history[0] = change with { After = state with { First = state.First with { Id = Guid.NewGuid().ToString() } } }; break;
            case "allocation-parent": history[0] = change with { After = state with { First = state.First with { ServiceId = Guid.NewGuid().ToString() } } }; break;
            case "allocation-borrowed": history[0] = change with { After = state with { First = state.First with { Id = borrowedObjects.Keys.Last() } } }; break;
            case "allocation-actor-credential": history[0] = change with { After = state with { First = state.First with { Id = credentials.First(c => c.Owned).Id } } }; break;
            case "history-root": history[0] = change with { Root = "foreign" }; break;
            case "history-request": history[0] = change with { Request = "foreign" }; break;
            case "history-commit": history[0] = change with { Commit = "foreign" }; break;
            case "history-protected-input": history[0] = change with { InputHash = "foreign" }; break;
            case "history-missing": return history.Skip(1).ToArray();
            case "history-duplicate": return [history[0], .. history];
            case "history-reordered": return history.Reverse().ToArray();
        }
        return history;
    }
    private ProxyPermissionCollections CollectionPacket(ProxyPermissionStep step)
    {
        var snapshot = collections.Snapshot(); snapshot = snapshot with { History = CorruptHistory(snapshot.History, step) };
        if (step == ProxyPermissionStep.Open)
            snapshot = Fault switch
            {
                "allocation-missing" => snapshot with { Active = snapshot.Active.Skip(1).ToArray() },
                "collection-inventory-missing" => snapshot with { Inventory = snapshot.Inventory.Skip(1).ToArray() },
                _ => snapshot
            };
        if (step is ProxyPermissionStep.ObserveBefore or ProxyPermissionStep.ObserveAfter or ProxyPermissionStep.Close)
            snapshot = Fault switch
            {
                "retirement-missing" => snapshot with { Retired = snapshot.Retired.Skip(1).ToArray() },
                "retirement-duplicate" when snapshot.Retired.Length > 0 => snapshot with { Retired = [snapshot.Retired[0], .. snapshot.Retired] },
                "retirement-reordered" => snapshot with { Retired = snapshot.Retired.Reverse().ToArray() },
                "retirement-substituted" when snapshot.Retired.Length > 0 => snapshot with { Retired = [snapshot.Retired[0] with { Credential = "foreign" }, .. snapshot.Retired.Skip(1)] },
                "deleted-inventory-missing" => snapshot with { Deleted = snapshot.Deleted.Skip(1).ToArray() },
                "orphaned-replaced-collection" when snapshot.Deleted.Length > 0 => snapshot with { Active = [.. snapshot.Active, snapshot.Deleted[0]] },
                _ => snapshot
            };
        return snapshot;
    }
}
