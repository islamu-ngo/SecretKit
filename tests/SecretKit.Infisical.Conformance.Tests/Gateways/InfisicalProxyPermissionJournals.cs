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
    private void Clear() { ingress.Clear(); commits.Clear(); decisions.Clear(); changes.Clear(); }
    private ProxyPermissionSigned<T> Sign<T>(ProxyPermissionStep step, ProxyPermissionJournal journal, T content) => writers[journal].Sign(root!, step, content);
    private ProxyPermissionJoin[] Joins()
    {
        if (closed) return [];
        var joins = actors.Select((actor, i) => new ProxyPermissionJoin(actor.Principal,
            actor.Kind == MemberPermissionActorKind.User ? "user" : "machine", actor.Organization,
            root!.ScopeProfile == ProxyPermissionScope.Project ? Id(ProxyPermissionPlan.Project) : "", Id(plan!.ActorMembership(i)),
            i == 0 && (!ProxyPermissionContract.Create(root.Operation) || assigned && !copied), i == 0 && (!ProxyPermissionContract.Create(root.Operation) || assigned && !copied) ? Id(plan.PolicyKey) : "",
            i == 0 && (!ProxyPermissionContract.Create(root.Operation) || assigned && !copied) ? Fault == "wrong-role-binding" ? "foreign-role" : plan.Slug : "no-access", true, "accepted")).ToList();
        if (copied) joins.Add(new(actors[0].Principal, "user", Organization, Id(ProxyPermissionPlan.CopyProject), Id(plan!.ActorMembership(0, true)),
            true, Id(ProxyPermissionPlan.CopiedRole), Fault == "wrong-role-binding" ? "foreign-role" : plan.Slug, true, "accepted"));
        return joins.ToArray();
    }
    private ProxyPermissionPacket Packet(ProxyPermissionStep step)
    {
        bool open = step == ProxyPermissionStep.Open, observe = step is ProxyPermissionStep.ObserveBefore or ProxyPermissionStep.ObserveAfter;
        var issue = issuanceBindings.ToArray(); var storage = storageBindings.ToArray();
        if (open && issue.Length > 1)
        {
            switch (Fault)
            {
                case "binding-substitution": storage[0] = storage[0] with { CanonicalId = Guid.NewGuid().ToString() }; break;
                case "binding-request": issue[1] = issue[1] with { Request = issue[0].Request }; storage = issue.ToArray(); break;
                case "binding-commit": issue[1] = issue[1] with { Commit = issue[0].Commit }; storage = issue.ToArray(); break;
                case "binding-duplicate": issue[1] = issue[1] with { CanonicalId = issue[0].CanonicalId }; storage = issue.ToArray(); break;
                case "binding-work": issue[0] = issue[0] with { Work = "foreign-work" }; storage = issue.ToArray(); break;
                case "binding-input": issue[0] = issue[0] with { InputHash = "foreign-input" }; storage = issue.ToArray(); break;
                case "input-configuration":
                    int selected = Array.FindIndex(issue, b => b.Kind == "service");
                    issue[selected] = issue[selected] with { InputHash = ProxyPermissionContract.Hash(new { Host = "foreign.example.invalid" }) }; storage = issue.ToArray(); break;
                case "binding-scope": issue[0] = issue[0] with { Scope = "foreign-scope" }; storage = issue.ToArray(); break;
                case "binding-borrowed": issue[0] = issue[0] with { CanonicalId = borrowedObjects.Keys.First() }; storage = issue.ToArray(); break;
                case "binding-missing": issue = issue.Skip(1).ToArray(); break;
            }
        }
        var credentialRows = credentials.ToArray(); var joins = Joins(); var inventory = states.Values.OrderBy(s => s.Row).ToArray();
        if (open && Fault == "actor-kind") credentialRows[0] = credentialRows[0] with { Kind = credentialRows[0].Kind == MemberPermissionActorKind.User ? MemberPermissionActorKind.Machine : MemberPermissionActorKind.User };
        if (open && Fault == "credential-wrong-actor") credentialRows[0] = credentialRows[0] with { Principal = Authorities.Observer };
        if (open && Fault == "membership-wrong-member") joins[0] = joins[0] with { Principal = Authorities.Observer };
        if (open && Fault == "missing-inventory") inventory = inventory.Skip(1).ToArray();
        var allPolicies = new[] { policy, copiedPolicy }.OfType<ProxyPermissionPolicy>().OrderBy(p => p.Resource).ToArray();
        var committed = observe || step == ProxyPermissionStep.Settle ? commits.ToArray() : [];
        if (step == ProxyPermissionStep.Settle && Fault == "wrong-policy-target" && committed.Length == 1)
        { committed[0] = committed[0] with { Policy = committed[0].Policy with { Resource = Guid.NewGuid().ToString() } }; allPolicies = [committed[0].Policy]; }
        var intents = plan!.Intents.ToArray();
        if (open && Fault == "intent-mutation") intents[0] = intents[0] with { Input = "changed" };
        var packet = new ProxyPermissionPacket(
            Sign(step, ProxyPermissionJournal.Ownership, new ProxyPermissionOwner(intents, resources.Values.ToArray(), Borrowed(), borrowed, true, true,
                settled || closed, settled || closed, open && Fault == "pending-issuer" ? 1 : 0, closed ? 0 : 1, open ? actors : [])),
            Sign(step, ProxyPermissionJournal.Ingress, new ProxyPermissionIngressLog(observe || step == ProxyPermissionStep.Settle ? ingress.ToArray() : [],
                open && Fault == "dispatch-history-missing" ? collectionDispatches.Skip(1).ToArray() : collectionDispatches.ToArray())),
            Sign(step, ProxyPermissionJournal.Policy, new ProxyPermissionPolicies(allPolicies, committed)),
            Sign(step, ProxyPermissionJournal.Storage, new ProxyPermissionStorage(storage, inventory, observe ? changes.ToArray() : [], CollectionHistory(step), templates, collectionHistory.Where(c => c.After is null).Select(c => c.Before!).ToArray())),
            Sign(step, ProxyPermissionJournal.Issuer, new ProxyPermissionIssuance(issue, credentialRows)),
            Sign(step, ProxyPermissionJournal.Membership, joins), Sign(step, ProxyPermissionJournal.Access, observe ? decisions.ToArray() : []),
            Sign(step, ProxyPermissionJournal.Collection, CollectionPacket(step)), []);
        var seals = new List<ProxyPermissionSigned<MemberPermissionSeal>>();
        Add(ProxyPermissionJournal.Ownership, packet.Owner.Payload); Add(ProxyPermissionJournal.Ingress, packet.Ingress.Payload);
        Add(ProxyPermissionJournal.Policy, packet.Policy.Payload); Add(ProxyPermissionJournal.Storage, packet.Storage.Payload);
        Add(ProxyPermissionJournal.Issuer, packet.Issuer.Payload); Add(ProxyPermissionJournal.Membership, packet.Membership.Payload); Add(ProxyPermissionJournal.Access, packet.Access.Payload); Add(ProxyPermissionJournal.Collection, packet.Collection.Payload);
        return packet with { Seals = open && Fault == "missing-seal" ? seals.Skip(1).ToArray() : seals.ToArray() };
        void Add<T>(ProxyPermissionJournal journal, T payload) => seals.Add(Sign(step, journal,
            new MemberPermissionSeal(ProxyPermissionContract.Hash(payload), !(open && Fault == "nonterminal"), 0, 1)));
    }
}
