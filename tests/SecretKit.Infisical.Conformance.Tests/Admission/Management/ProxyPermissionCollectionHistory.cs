namespace SecretKit.Infisical.Conformance.Tests;

// Credentials belong to the service aggregate, not to independently dispatched
// resources. The ordered revision is the allocation key: (service, version, slot).
// Independent storage and collection signatures must close over the whole history.
internal sealed class ProxyPermissionCollectionHistory(ProxyPermissionRoot root, ProxyPermissionPlan plan)
{
    private ProxyPermissionCollectionChange[] accepted = [];
    private ProxyPermissionCollectionDispatch[] dispatches = [];
    internal void Check(ProxyPermissionPacket packet, ProxyPermissionStep step)
    {
        var source = packet.Collection.Payload.Content; var storage = packet.Storage.Payload.Content;
        string code = step == ProxyPermissionStep.Close ? "cleanup-incomplete" : "effect-mismatch";
        void Require(bool value) => ProxyPermissionContract.Require(value, code);
        Require(source.History.SequenceEqual(storage.CollectionHistory) && source.History.Length >= accepted.Length &&
            source.History.Take(accepted.Length).SequenceEqual(accepted));
        var ingressHistory = packet.Ingress.Payload.Content.Collection;
        Require(ingressHistory.Length >= dispatches.Length && ingressHistory.Take(dispatches.Length).SequenceEqual(dispatches) &&
            ingressHistory.Select(d => d.Request).Distinct().Count() == ingressHistory.Length && ingressHistory.Length == source.History.Length);
        var live = new Dictionary<string, ProxyPermissionState>();
        var deletedServices = new Dictionary<string, ProxyPermissionState>();
        var identities = new Dictionary<string, (string Service, int Slot)>();
        var last = new Dictionary<string, ProxyPermissionCredentialState>();
        var retired = new List<ProxyPermissionRetirement>();
        var requests = new HashSet<string>(); var commits = new HashSet<string>();
        var issued = new ProxyPermissionIssued([], storage.Bindings);
        foreach (var change in source.History)
        {
            var state = change.After ?? change.Before;
            Require(state is not null && change.Root == root.Id && change.Nonce == root.Nonce &&
                MemberPermissionContract.Text(change.Request) && MemberPermissionContract.Text(change.Commit) &&
                requests.Add(change.Request) && commits.Add(change.Commit));
            var dispatch = ingressHistory.SingleOrDefault(d => d.Request == change.Request);
            Require(dispatch is not null && dispatch.Root == root.Id && dispatch.Nonce == root.Nonce && dispatch.Service == state!.Target &&
                dispatch.InputHash == change.InputHash && dispatch.Phase is "setup" or "action" or "close");
            if (dispatch!.Phase == "close") Require(change.After is null && change.Request == root.Id + ":close:" + state!.Target);
            if (dispatch.Phase == "setup") Require(change.Before is null && change.After is not null);
            var binding = storage.Bindings.SingleOrDefault(b => b.CanonicalId == state!.Target);
            var row = plan.Rows.SingleOrDefault(r => r.Key == state!.Row);
            Require(binding is not null && row is not null && binding.Intent == row.Target && binding.Kind == "service" &&
                binding.Scope == state!.Project && change.Before == live.GetValueOrDefault(state.Target));
            if (change.Before is { } previous)
            {
                foreach (var c in previous.Credentials)
                {
                    string reason = change.After is null ? "service-retired" : change.After.Credentials[c.Slot].Id == c.Id ? "retained-id" : "replaced-id";
                    retired.Add(new(previous.Target, previous.Version, c.Slot, c.Id, c.Fingerprint, change.Request, reason));
                }
            }
            else Require(binding!.Request == change.Request && binding.Commit == change.Commit && state!.Version == 1 &&
                MemberPermissionContract.Text(change.InputHash));
            if (change.After is { } next)
            {
                Require(next.Version == (change.Before?.Version ?? 0) + 1 && plan.Matches(row!, issued, next, next.Version) &&
                    next.Version is 1 or 2 && next.First.Id != next.Second.Id);
                foreach (var c in next.Credentials)
                {
                    Require(Guid.TryParse(c.Id, out _) && !storage.Bindings.Any(b => b.CanonicalId == c.Id) &&
                        !packet.Owner.Payload.Content.Borrowed.Any(b => b.Id == c.Id));
                    if (identities.TryGetValue(c.Id, out var owner))
                        Require(owner == (next.Target, c.Slot) && change.Before?.Credentials[c.Slot].Id == c.Id);
                    else identities.Add(c.Id, (next.Target, c.Slot));
                    last[c.Id] = c;
                }
                live[next.Target] = next;
            }
            else
            {
                Require(change.Before is not null); deletedServices.Add(state!.Target, change.Before!); live.Remove(state.Target);
            }
        }
        var active = live.Values.SelectMany(s => s.Credentials).OrderBy(c => c.Id).ToArray();
        var deleted = last.Values.Where(c => !active.Any(a => a.Id == c.Id)).OrderBy(c => c.Id).ToArray();
        Require(active.Select(c => c.Id).Distinct().Count() == active.Length &&
            source.Active.OrderBy(c => c.Id).SequenceEqual(active) && source.Deleted.OrderBy(c => c.Id).SequenceEqual(deleted) &&
            source.Retired.SequenceEqual(retired) &&
            source.DeletedServices.OrderBy(s => s.Target).SequenceEqual(deletedServices.Values.OrderBy(s => s.Target)) &&
            storage.Deleted.OrderBy(s => s.Target).SequenceEqual(deletedServices.Values.OrderBy(s => s.Target)) && source.Inventory.OrderBy(s => s.Target).SequenceEqual(live.Values.OrderBy(s => s.Target)) &&
            storage.Inventory.OrderBy(s => s.Target).SequenceEqual(live.Values.OrderBy(s => s.Target)));
        Require(packet.Owner.Payload.Content.Remaining.Where(r => storage.Bindings.Any(b => b.Intent == r.Intent && b.Kind == "service"))
            .Select(r => r.CanonicalId).Order().SequenceEqual(live.Keys.Order()));
        var added = source.History.Skip(accepted.Length).ToArray();
        if (step is ProxyPermissionStep.ObserveBefore or ProxyPermissionStep.ObserveAfter)
        {
            var mutations = storage.Changes.Where(c => c.Before != c.After).ToArray();
            Require(added.Length == mutations.Length);
            foreach (var mutation in mutations)
            {
                var change = added.SingleOrDefault(c => c.Request == mutation.Request);
                var ingress = packet.Ingress.Payload.Content.Window.SingleOrDefault(i => i.Request == mutation.Request);
                Require(change is not null && change.Before == mutation.Before && change.After == mutation.After &&
                    ingress is not null && ingress.Authorized && ingress.Phase == "action" &&
                    change.InputHash == ingress.BodyHash);
            }
        }
        else if (step is ProxyPermissionStep.Open or ProxyPermissionStep.After)
            Require(added.All(c => c.Before is null && c.After is not null));
        else if (step != ProxyPermissionStep.Close) Require(added.Length == 0);
        if (step == ProxyPermissionStep.Close)
            Require(live.Count == 0 && source.Active.Length == 0 && packet.Owner.Payload.Content.IssuerFence && packet.Owner.Payload.Content.IngressFence);
        dispatches = ingressHistory.ToArray();
        accepted = source.History.ToArray();
    }
}
