using System.Collections.Concurrent;
using System.Net;
using System.Net.Sockets;
using System.Security.Cryptography;
using System.Text;
using System.Text.Json;
using System.Text.Json.Nodes;
using SecretKit.TestFixtures;

namespace SecretKit.Infisical.Conformance.Tests;

internal sealed partial class InfisicalProxyPermissionFixture
{
    private void Open()
    {
        Opens++; CommitCreation(ProxyPermissionPlan.OtherOrganization);
        if (Fault == "partial-open") throw new NativeCaseFailureException("observer-unavailable");
        CommitCreation(ProxyPermissionPlan.Project); CommitCreation(ProxyPermissionPlan.OtherProject);
        foreach (string key in new[] { "issuer-work", "dispatch-work", "registration", "canary", "owned-key" }) CommitCreation(key);
        ownedKey = ECDsa.Create(ECCurve.NamedCurves.nistP256);
        actors = Enumerable.Range(0, root!.ScopeProfile == ProxyPermissionScope.Organization ? 4 : 3).Select(IssueActor).ToArray();
        foreach (var row in plan!.Rows.Where(r => r.Window != "copy")) Bootstrap(row);
        assigned = !root.Operation.Split('.').Last().StartsWith("Create", StringComparison.Ordinal);
        if (assigned)
        {
            CommitCreation(plan.PolicyKey);
            string[] actions = ["read", "create", "edit", "delete"];
            string baseline = actions[(Array.IndexOf(actions, ProxyPermissionContract.Wire(root.Action)) + 1) % actions.Length];
            policy = new(Id(plan.PolicyKey), revision, actors[0].Principal, actors[0].Kind, Organization,
                root.ScopeProfile == ProxyPermissionScope.Project ? Id(ProxyPermissionPlan.Project) : "", "proxied-services", [baseline], ["witness", "/closed"], plan.Slug, "bootstrap-policy");
        }
        if (Fault == "delayed-issuer")
        {
            delayed = IssueDelayedAsync(); throw new NativeCaseFailureException("observer-unavailable");
        }
        if (Fault == "lost-open") throw new NativeCaseFailureException("observer-unavailable");
    }
    private async Task IssueDelayedAsync()
    {
        IssuerEntered.TrySetResult(); await IssuerRelease.Task.WaitAsync(shutdown.Token);
        lock (gate) CommitCreation(ProxyPermissionPlan.Deferred, admitted: true);
    }
    private void Bootstrap(ProxyPermissionRow row)
    {
        if (Id(row.Folder).Length == 0) CommitCreation(row.Folder);
        if (row.Action == ProxyPermissionAction.Create) return;
        CommitCreation(row.Target);
        var body = BootstrapBody(row);
        var binding = storageBindings.Single(b => b.Intent == row.Target);
        Store(row, body, 1, binding.Request, binding.Commit, plan!.ExpectedInput(row, 1));
    }
    internal ProxyPermissionPacket Step(ProxyPermissionRoot selected, ProxyPermissionStep step, string? capability)
    {
        lock (gate)
        {
            if (step == ProxyPermissionStep.Reserve)
            {
                ProxyPermissionContract.Require(root is null && capability == "proxy-capability" && selected.Origin == Origin.AbsoluteUri &&
                    selected.Organization == Organization && selected.Authorities == Authorities && ProxyPermissionContract.Hash(Profile) == ProxyPermissionContract.Hash(selected.Profile));
                root = selected; plan = new(selected);
                if (Fault == "collision") throw new NativeCaseFailureException("observer-unavailable");
            }
            ProxyPermissionContract.Require(root is not null && ProxyPermissionContract.Hash(root) == ProxyPermissionContract.Hash(selected) && !closed &&
                (step == ProxyPermissionStep.Close || stage == (int)step));
            if (step != ProxyPermissionStep.Close) stage++;
            switch (step)
            {
                case ProxyPermissionStep.Open: Open(); break;
                case ProxyPermissionStep.Before: Clear(); window = "before"; break;
                case ProxyPermissionStep.Arm: Clear(); window = ""; armed = true; break;
                case ProxyPermissionStep.Settle: settled = true; break;
                case ProxyPermissionStep.After:
                    ingress.RemoveAll(e => e.Phase != "activation"); commits.RemoveAll(c => !ingress.Any(e => e.Request == c.Request));
                    decisions.Clear(); changes.Clear(); window = "after"; break;
                case ProxyPermissionStep.ObserveBefore:
                case ProxyPermissionStep.ObserveAfter: window = ""; break;
                case ProxyPermissionStep.Close:
                    Closes++;
                    ProxyPermissionContract.Require(closing && (delayed is null || delayed.IsCompletedSuccessfully));
                    // Reconcile native IDs from original-root issuance AND storage, not the Open reply.
                    ProxyPermissionContract.Require(issuanceBindings.SequenceEqual(storageBindings));
                    foreach (var binding in storageBindings)
                        ProxyPermissionContract.Require(binding.IntentHash == ProxyPermissionContract.Hash(plan!.Intents.Single(i => i.Key == binding.Intent)) &&
                            !borrowed.Any(b => b.Id == binding.CanonicalId));
                    foreach (var binding in storageBindings)
                    {
                        var native = resources.SingleOrDefault(r => r.Value.CanonicalId == binding.CanonicalId);
                        if (native.Key is null) continue; // A witnessed downstream delete may already have removed it.
                        ProxyPermissionContract.Require(native.Value.Intent == binding.Intent);
                        resources.Remove(native.Key);
                    }
                    foreach (var state in collections.Snapshot().Inventory) Retire(state, root!.Id + ":close:" + state.Target, Guid.NewGuid().ToString("N"), ProxyPermissionContract.RawHash([]));
                    states.Clear(); configurations.Clear(); templates = []; credentials.Clear(); tokens.Clear(); policy = copiedPolicy = null;
                    foreach (var bytes in privateBuffers) CryptographicOperations.ZeroMemory(bytes);
                    ownedKey?.Dispose(); ownedKey = null; closed = settled = true; armed = false; window = "";
                    if (Fault == "cleanup") resources.Add("residual", new("canary", Id("canary")));
                    if (Fault == "borrowed-change") borrowedObjects[borrowedObjects.Keys.First()] = "modified";
                    break;
            }
            return Packet(step);
        }
    }
}
