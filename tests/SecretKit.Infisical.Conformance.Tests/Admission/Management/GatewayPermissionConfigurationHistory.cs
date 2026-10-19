using SecretKit.TestFixtures;

namespace SecretKit.Infisical.Conformance.Tests;

// Storage and the eighth authority independently sign complete config history.
// Native config ID is revision metadata: retention AND replacement are allowed.
internal sealed class GatewayPermissionConfigurationHistory(GatewayPermissionRoot root)
{
    private GatewayPermissionConfigurationChange[] accepted = [];
    internal void Check(GatewayPermissionPacket packet, GatewayPermissionStep step)
    {
        var configuration = packet.Configuration.Payload.Content;
        var storage = packet.Storage.Payload.Content;
        string code = step == GatewayPermissionStep.Close ? "cleanup-incomplete" : "effect-mismatch";
        void Require(bool value) => GatewayPermissionContract.Require(value, code);
        Require(configuration.History.SequenceEqual(storage.ConfigurationHistory) && configuration.History.Length >= accepted.Length &&
            configuration.History.Take(accepted.Length).SequenceEqual(accepted));
        var live = new Dictionary<string, GatewayPermissionState>();
        var revisions = new HashSet<string>(); var retired = new List<GatewayPermissionRetirement>();
        foreach (var change in configuration.History)
        {
            var state = change.After ?? change.Before;
            Require(state is not null && change.Root == root.Id && change.Nonce == root.Nonce && MemberPermissionContract.Text(change.Request));
            var binding = storage.Bindings.SingleOrDefault(b => b.CanonicalId == state!.Target);
            Require(binding is not null && binding.Kind == "gateway" && binding.Scope == state!.Organization &&
                change.Before == live.GetValueOrDefault(state!.Target));
            if (change.Before is { } previous)
            {
                string reason = change.After is null ? "root-close" : previous.ConfigId == change.After.ConfigId ? "retained-id" : "replaced-id";
                Require(change.Retirement == new GatewayPermissionRetirement(previous.Target, previous.ConfigId, previous.ConfigRevision, change.Request, reason));
                retired.Add(change.Retirement!);
            }
            else Require(change.Retirement is null && binding!.Request == change.Request && state!.Version == 1);
            if (change.After is { } next)
            {
                Require(Guid.TryParse(next.ConfigId, out _) && MemberPermissionContract.Text(next.ConfigRevision) && revisions.Add(next.ConfigRevision) &&
                    !packet.Owner.Payload.Content.Borrowed.Any(b => b.Kind == "borrowed-config" && b.Id == next.ConfigId) &&
                    next.Project == "" && next.Version == (change.Before?.Version ?? 0) + 1 &&
                    DateTimeOffset.TryParse(next.ConfigCreatedAt, out _) && DateTimeOffset.TryParse(next.ConfigUpdatedAt, out _) &&
                    (change.Before is null || next.Row == change.Before.Row && next.Target == change.Before.Target && next.Organization == change.Before.Organization));
                live[next.Target] = next;
            }
            else
            {
                Require(change.Before is not null && change.Request == root.Id + ":close:" + state!.Target);
                live.Remove(state!.Target);
            }
        }
        Require(configuration.Retired.SequenceEqual(retired) && configuration.Inventory.OrderBy(s => s.Target).SequenceEqual(live.Values.OrderBy(s => s.Target)) &&
            storage.Inventory.OrderBy(s => s.Target).SequenceEqual(live.Values.OrderBy(s => s.Target)));
        var added = configuration.History.Skip(accepted.Length).ToArray();
        if (step is GatewayPermissionStep.ObserveBefore or GatewayPermissionStep.ObserveAfter)
        {
            var mutations = storage.Changes.Where(c => c.Before != c.After).ToArray();
            Require(added.Length == mutations.Length);
            foreach (var mutation in mutations)
            {
                var change = added.SingleOrDefault(c => c.Request == mutation.Request);
                var ingress = packet.Ingress.Payload.Content.SingleOrDefault(i => i.Request == mutation.Request);
                Require(change is not null && change.Before == mutation.Before && change.After == mutation.After &&
                    ingress is not null && ingress.Authorized && ingress.Phase == "action");
            }
        }
        else if (step is not (GatewayPermissionStep.Open or GatewayPermissionStep.Close)) Require(added.Length == 0);
        if (step == GatewayPermissionStep.Open) Require(added.All(c => c.Before is null && c.After is not null));
        if (step == GatewayPermissionStep.Close) Require(live.Count == 0 && packet.Owner.Payload.Content.IssuerFence && packet.Owner.Payload.Content.IngressFence);
        accepted = configuration.History.ToArray();
    }
}
