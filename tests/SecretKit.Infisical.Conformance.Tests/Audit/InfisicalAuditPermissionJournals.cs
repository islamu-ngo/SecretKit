namespace SecretKit.Infisical.Conformance.Tests;

// Eight fixture writer keys simulate distinct trust roles. They are NOT evidence
// of independently administered native processes or deployment authority.
internal sealed partial class InfisicalAuditPermissionFixture
{
    private AuditPermissionSigned<T> Sign<T>(AuditPermissionStep step, AuditPermissionJournal journal, T content) => writers[journal].Sign(root!, step, content);
    private AuditPermissionJoin[] Joins()
    {
        if (closed) return [];
        var joins = actors.Select((actor, i) => new AuditPermissionJoin(actor.Principal,
            actor.Kind == MemberPermissionActorKind.User ? "user" : "machine", actor.Organization,
            root!.ScopeProfile == AuditPermissionScope.Project ? Id(AuditPermissionPlan.Project) : "", Id(plan!.ActorMembership(i)),
            i == 0 && (!AuditPermissionContract.Create(root.Operation) || assigned && !copied), i == 0 && (!AuditPermissionContract.Create(root.Operation) || assigned && !copied) ? Id(plan.PolicyKey) : "",
            i == 0 && (!AuditPermissionContract.Create(root.Operation) || assigned && !copied) ? Fault == "wrong-role-binding" ? "foreign-role" : plan.Slug : "no-access", true, "accepted")).ToList();
        if (copied) joins.Add(new(actors[0].Principal, "user", Organization, Id(AuditPermissionPlan.CopyProject), Id(plan!.ActorMembership(0, true)),
            true, Id(AuditPermissionPlan.CopiedRole), Fault == "wrong-role-binding" ? "foreign-role" : plan.Slug, true, "accepted"));
        return joins.ToArray();
    }
    private AuditPermissionPacket Packet(AuditPermissionStep step)
    {
        bool open = step == AuditPermissionStep.Open, published = step == AuditPermissionStep.PublishedBefore;
        var issue = issuanceBindings.ToArray(); var storage = storageBindings.ToArray();
        if (open && issue.Length > 1)
        {
            switch (Fault)
            {
                case "binding-substitution": storage[0] = storage[0] with { CanonicalId = Guid.NewGuid().ToString() }; break;
                case "binding-duplicate": issue[1] = issue[1] with { CanonicalId = issue[0].CanonicalId }; storage = issue.ToArray(); break;
                case "binding-work": issue[0] = issue[0] with { Work = "foreign-work" }; storage = issue.ToArray(); break;
                case "binding-input": issue[0] = issue[0] with { InputHash = "foreign-input" }; storage = issue.ToArray(); break;
                case "binding-scope": issue[0] = issue[0] with { Scope = "foreign-scope" }; storage = issue.ToArray(); break;
                case "binding-borrowed": issue[0] = issue[0] with { CanonicalId = borrowedObjects.Keys.First() }; storage = issue.ToArray(); break;
                case "binding-missing": issue = issue.Skip(1).ToArray(); break;
            }
        }
        var credentialRows = credentials.ToArray(); var joins = Joins(); var inventory = states.ToArray();
        var history = credentialHistory.ToArray(); var events = publications.ToArray(); var requests = ingress.ToArray();
        var seeds = seedCommits.ToArray();
        if (open && Fault == "actor-kind") { credentialRows[0] = credentialRows[0] with { Kind = MemberPermissionActorKind.User }; history[0] = credentialRows[0]; }
        if (open && Fault == "credential-wrong-actor") { credentialRows[^1] = credentialRows[^1] with { Principal = Authorities.Observer }; history[^1] = credentialRows[^1]; }
        if (open && Fault == "membership-wrong-member") joins[0] = joins[0] with { Principal = Authorities.Observer };
        if (published && events.Length > 0)
        {
            switch (Fault)
            {
                case "causal-gap": events = events.SkipLast(1).ToArray(); inventory = inventory.SkipLast(1).ToArray(); break;
                case "producer-censorship": seeds = seeds.SkipLast(1).ToArray(); events = events.SkipLast(1).ToArray(); inventory = inventory.SkipLast(1).ToArray(); break;
                case "omitted-row": inventory = inventory.SkipLast(1).ToArray(); break;
                case "duplicate-row": inventory[1] = inventory[0]; break;
                case "fabricated-row": inventory[0] = inventory[0] with { Id = Guid.NewGuid().ToString() }; break;
                case "wrong-parent": events[0] = events[0] with { ParentRequest = events[1].ParentRequest }; break;
                case "wrong-input": events[0] = events[0] with { InputHash = "foreign-input" }; break;
                case "wrong-event-actor": events[0] = events[0] with { Actor = Authorities.Runtime }; break;
                case "wrong-event-kind": events[0] = events[0] with { Kind = MemberPermissionActorKind.User }; break;
                case "wrong-event-credential": events[0] = events[0] with { CredentialId = "foreign-credential" }; break;
                case "wrong-event-scope": events[0] = events[0] with { Project = Id(AuditPermissionPlan.OtherProject) }; break;
                case "wrong-event-type": events[0] = events[0] with { EventType = "view-audit-logs" }; break;
                case "wrong-event-class": events[0] = events[0] with { EventClass = SecretKit.Infisical.Management.AuditEventClass.DataAccess }; break;
                case "late-event": events[0] = events[0] with { At = root!.Until.AddSeconds(1) }; break;
                case "duplicate-event": events[1] = events[0]; break;
                case "canonical-parent": inventory[0] = inventory[0] with { ParentRequest = "foreign-request" }; break;
                case "canonical-binding": inventory[0] = inventory[0] with { Publication = "foreign-event" }; break;
            }
        }
        var allPolicies = new[] { policy, copiedPolicy }.OfType<AuditPermissionPolicy>().OrderBy(p => p.Resource).ToArray();
        var committed = commits.ToArray();
        if (step == AuditPermissionStep.Settle && Fault == "wrong-policy-target" && committed.Length == 1)
        { committed[0] = committed[0] with { Policy = committed[0].Policy with { Resource = Guid.NewGuid().ToString() } }; allPolicies = [committed[0].Policy]; }
        var intents = plan!.Intents.ToArray();
        if (open && Fault == "intent-mutation") intents[0] = intents[0] with { Input = "changed" };
        var packet = new AuditPermissionPacket(
            Sign(step, AuditPermissionJournal.Ownership, new AuditPermissionOwner(intents, resources.Values.ToArray(), Borrowed(), true, true,
                settled || closed, settled || closed, producerFence, publicationFence, open && Fault == "pending-issuer" ? 1 : 0,
                closed ? 0 : 1, open ? actors : [], closed ? AuditPermissionContract.Hash(inventory) : "", root!.RetainUntil)),
            Sign(step, AuditPermissionJournal.Ingress, requests),
            Sign(step, AuditPermissionJournal.Policy, new AuditPermissionPolicies(allPolicies, committed)),
            Sign(step, AuditPermissionJournal.Storage, new AuditPermissionStorage(storage, inventory, seeds, AuditPermissionContract.Hash(inventory))),
            Sign(step, AuditPermissionJournal.Issuer, new AuditPermissionIssuance(issue, credentialRows, history)),
            Sign(step, AuditPermissionJournal.Membership, joins), Sign(step, AuditPermissionJournal.Access, decisions.ToArray()),
            Sign(step, AuditPermissionJournal.Publisher, new AuditPermissionPublication(events, producerFence, publicationFence && !(published && Fault == "unsealed-publication"),
                0, outbox.Count + (published && Fault == "pending-publication" ? 1 : 0), events.Length, events.Length, AuditPermissionContract.Hash(events))), []);
        var seals = new List<AuditPermissionSigned<MemberPermissionSeal>>();
        Add(AuditPermissionJournal.Ownership, packet.Owner.Payload); Add(AuditPermissionJournal.Ingress, packet.Ingress.Payload);
        Add(AuditPermissionJournal.Policy, packet.Policy.Payload); Add(AuditPermissionJournal.Storage, packet.Storage.Payload);
        Add(AuditPermissionJournal.Issuer, packet.Issuer.Payload); Add(AuditPermissionJournal.Membership, packet.Membership.Payload);
        Add(AuditPermissionJournal.Access, packet.Access.Payload); Add(AuditPermissionJournal.Publisher, packet.Publisher.Payload);
        return packet with { Seals = open && Fault == "missing-seal" ? seals.Skip(1).ToArray() : seals.ToArray() };
        void Add<T>(AuditPermissionJournal journal, T payload) => seals.Add(Sign(step, journal,
            new MemberPermissionSeal(AuditPermissionContract.Hash(payload), !(open && Fault == "nonterminal"), 0, 1)));
    }
}
