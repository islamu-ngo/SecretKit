using SecretKit.Core;

namespace SecretKit.Infisical.Conformance.Tests;

internal sealed class TemplatePrincipalTrial : IAsyncDisposable
{
    private readonly ITemplatePrincipalSource source;
    private readonly TemplatePrincipalVerifier verifier;
    private readonly int seconds;
    private readonly List<TemplatePrincipalCredential> credentials = [];
    private readonly List<TemplatePrincipalIssued> copies = [];
    private TemplatePrincipalBorrowed[]? borrowed;
    private TemplatePrincipalResource[] enrolled = [];
    private int stage;
    private bool failed, busy, closed;
    private string intent = "";
    private TemplatePrincipalCommit[] commits = [];
    private string? baselineRevision;
    internal TemplatePrincipalRoot Root { get; }
    internal TemplatePrincipalIssued Issued { get; private set; } = null!;
    internal TemplatePrincipalOutcome Outcome { get; private set; }
    internal TemplatePrincipalReceipt? Original { get; private set; }
    internal IReadOnlyList<TemplatePrincipalCredential> Credentials => credentials;
    private TemplatePrincipalTrial(ITemplatePrincipalSource source, TemplatePrincipalRoot root, int seconds)
    {
        this.source = source; Root = root; this.seconds = seconds;
        verifier = new(root);
    }
    internal static async ValueTask<TemplatePrincipalTrial> OpenAsync(ITemplatePrincipalSource source,
        TemplatePrincipalRoot root, SecretMaterial capability, int seconds, Action<TemplatePrincipalTrial> retain,
        CancellationToken token)
    {
        TemplatePrincipalContract.Profile(root.Profile);
        TemplatePrincipalContract.Require(seconds is >= 1 and <= 300 && root.Authorities.All.All(TemplatePrincipalContract.Text) &&
            root.Authorities.All.Distinct().Count() == 5 && root.Source == source.Identity && root.Kind == source.Kind &&
            TemplatePrincipalContract.CasesInventory().Any(c => c.Operation == root.Operation &&
                c.Variant == root.Variant && c.Boundary == root.Boundary), "missing-input");
        var trial = new TemplatePrincipalTrial(source, root, seconds);
        retain(trial); // Root recovery is installed BEFORE Reserve or any creation.
        await trial.StepAsync(TemplatePrincipalStep.Reserve, capability, null, token);
        await trial.StepAsync(TemplatePrincipalStep.Open, null, null, token);
        return trial;
    }
    internal void AddCredential(string principal, string project, string credential, SecretMaterial material)
    {
        TemplatePrincipalContract.Require(!closed && !failed && !busy &&
            principal == (project == Issued.BeforeProject ? Issued.BeforeManaged : Issued.AfterManaged));
        char[] chars = material.ExportCharacters();
        byte[] bytes;
        try { bytes = System.Text.Encoding.UTF8.GetBytes(chars); } finally { Array.Clear(chars); }
        credentials.Add(new(principal, Issued.ManagedName, "managed", project, credential,
            TemplatePrincipalContract.HashBytes(bytes), bytes));
    }
    internal async ValueTask BeginAsync(bool after, CancellationToken token) =>
        await StepAsync(after ? TemplatePrincipalStep.After : TemplatePrincipalStep.Before, null, null, token);
    internal async ValueTask ObserveAsync(bool after, TemplatePrincipalAttempt[] attempts, CancellationToken token)
    {
        var packet = await StepAsync(after ? TemplatePrincipalStep.ObserveAfter : TemplatePrincipalStep.ObserveBefore,
            null, null, token);
        failed = true;
        var members = packet.Memberships.Payload.Content;
        var accesses = packet.Access.Payload.Content;
        var issuers = packet.Issuers.Payload.Content;
        string project = after ? Issued.AfterProject : Issued.BeforeProject;
        string managed = after ? Issued.AfterManaged : Issued.BeforeManaged;
        bool baselineControl = after && Root.Operation == TemplatePrincipalContract.Create &&
            Outcome == TemplatePrincipalOutcome.NonApplied;
        string environment = TemplatePrincipalContract.Environment(after, Outcome);
        string[] Roles(string field) => !after || Outcome == TemplatePrincipalOutcome.NonApplied ||
            Root.Operation == TemplatePrincipalContract.Update && TemplatePrincipalContract.Field(Root.Variant) == field &&
                Root.Variant.EndsWith(".omitted", StringComparison.Ordinal) ?
                    [Issued.ReaderRole] : [Issued.ReaderRole, Issued.MarkerRole];
        var selectedCredentials = credentials.Where(c => c.Kind == "user" && c.Principal != Issued.Users[2].Principal ||
            c.Kind == "managed" && c.Project == project).ToArray();
        TemplatePrincipalContract.Require(selectedCredentials.Count(c => c.Kind == "user") == 2 &&
            selectedCredentials.Count(c => c.Kind == "managed") ==
                (baselineControl || TemplatePrincipalContract.Present(Root, "projectManagedIdentities", after, Outcome) ? 1 : 0),
            "effect-mismatch");
        var expectedAttempts = new List<(string Actor, string Environment, bool Allowed)>();
        foreach (var c in selectedCredentials)
        {
            string field = c.Kind == "managed" ? "projectManagedIdentities" :
                c.Principal == Issued.Users[0].Principal ? "users" : "groups";
            bool allowed = baselineControl || TemplatePrincipalContract.Present(Root, field, after, Outcome);
            expectedAttempts.AddRange([(c.Principal, environment, allowed),
                (Issued.Users[2].Principal, environment, false), (Root.Authorities.Denied, environment, false),
                (c.Principal, environment, allowed), (c.Principal, "outside", false)]);
        }
        expectedAttempts.AddRange([(Root.Authorities.Runtime, environment, false), (Root.Authorities.Observer, environment, true)]);
        TemplatePrincipalContract.Require(attempts.Length == expectedAttempts.Count &&
            attempts.Zip(expectedAttempts).All(p => p.First.Principal == p.Second.Actor &&
                p.First.Environment == p.Second.Environment && p.First.Allowed == p.Second.Allowed) &&
            attempts.Where(a => a.Credential == "host").All(a => borrowed!.Any(b => b.Kind == "host-token" &&
                b.Id == a.Principal && b.Revision == a.Hash)), "effect-mismatch");
        var expected = new List<(string Actor, string Kind, string? GroupMember, string[] Roles)>();
        {
            if (baselineControl || TemplatePrincipalContract.Present(Root, "users", after, Outcome))
                expected.Add((Issued.Users[0].Principal, "user", null, Roles("users")));
            if (baselineControl || TemplatePrincipalContract.Present(Root, "groups", after, Outcome))
                expected.Add((Issued.GroupId, "group", Issued.Users[1].Principal, Roles("groups")));
            if (baselineControl || TemplatePrincipalContract.Present(Root, "projectManagedIdentities", after, Outcome))
                expected.Add((managed, "managed", null, Roles("projectManagedIdentities")));
        }
        TemplatePrincipalContract.Require(members.Length == expected.Count &&
            members.Select(m => (m.Project, m.Principal)).Distinct().Count() == members.Length &&
            expected.All(e => members.Any(m => m.Project == project && m.Principal == e.Actor && m.Kind == e.Kind &&
                m.GroupMember == e.GroupMember && m.Group == (e.Kind == "group" ? Issued.GroupId : null) &&
                m.Roles.SequenceEqual(e.Roles) && m.PolicyHash == TemplatePrincipalContract.PolicyHash(environment))) &&
            members.All(m => enrolled.Any(r => r.Kind == "membership" && r.Id == m.Id) &&
                TemplatePrincipalContract.Text(m.CopyRequest) && TemplatePrincipalContract.Text(m.Revision) &&
                m.Template == (after && Root.Operation == TemplatePrincipalContract.Create &&
                    Outcome != TemplatePrincipalOutcome.NonApplied ? Issued.TemplateId :
                    Root.Operation == TemplatePrincipalContract.Update ? Issued.TemplateId : Issued.SeedId)) &&
            accesses.Length == attempts.Length && accesses.Select(a => a.Request).Distinct().Count() == accesses.Length &&
            accesses.Zip(attempts).All(p => p.First.Principal == p.Second.Principal &&
                p.First.Credential == p.Second.Credential && p.First.CredentialHash == p.Second.Hash &&
                p.First.Project == p.Second.Project && p.First.Environment == p.Second.Environment &&
                p.First.Allowed == p.Second.Allowed && p.First.ValueHash == p.Second.ValueHash &&
                p.First.Key == Issued.Key && TemplatePrincipalContract.Text(p.First.Request)),
            "effect-mismatch");
        foreach (var attempt in attempts.Where(a => a.Credential != "host"))
        {
            TemplatePrincipalContract.Require(issuers.Count(i => i.Principal == attempt.Principal &&
                i.Credential == attempt.Credential && i.CredentialHash == attempt.Hash &&
                (i.Kind == "user" ? enrolled.Any(r => r.Kind == "organization-membership" && r.Id == i.Membership) :
                    i.Project == project && members.Any(m => m.Id == i.Membership && m.Principal == i.Principal)) &&
                TemplatePrincipalContract.Text(i.Request)) == 1,
                "effect-mismatch");
        }
        if (after && Outcome == TemplatePrincipalOutcome.Applied)
            TemplatePrincipalContract.Require(members.All(m => commits.Any(c => c.Revision == m.Revision &&
                c.ConfigurationHash == m.ConfigurationHash && c.Template == m.Template)), "effect-mismatch");
        // Access revisions must match the copied membership revision, not a latest
        // template GET or a DTO supplied by this caller.
        TemplatePrincipalContract.Require(accesses.Where(a => a.Allowed && a.Credential != "host")
            .All(a => members.Any(m => m.Revision == a.Revision && m.Project == a.Project &&
                (m.Principal == a.Principal || m.GroupMember == a.Principal))), "effect-mismatch");
        if (!after)
        {
            TemplatePrincipalContract.Require(members.Select(m => m.Revision).Distinct().Count() == 1);
            baselineRevision = members[0].Revision;
        }
        failed = false;
    }
    internal async ValueTask ArmAsync(string hash, CancellationToken token)
    {
        TemplatePrincipalContract.Require(TemplatePrincipalContract.Text(hash), "missing-input");
        intent = hash;
        await StepAsync(TemplatePrincipalStep.Arm, null, new(DispatchEvidence.NotDispatched, null, false, hash), token);
    }
    internal async ValueTask SettleAsync(TemplatePrincipalReceipt receipt, CancellationToken token)
    {
        var packet = await StepAsync(TemplatePrincipalStep.Settle, null, receipt, token);
        failed = true;
        Original = receipt;
        commits = packet.Templates.Payload.Content;
        var ingress = packet.Ingress.Payload.Content;
        bool presend = Root.Boundary == "cancellation-boundary", lost = Root.Boundary == "lost-response-no-replay",
            denied = Root.Boundary == "denied-authority";
        string path = "/api/v1/project-templates" + (Root.Operation == TemplatePrincipalContract.Create ? "" : "/" + Issued.TemplateId);
        TemplatePrincipalContract.Require(receipt.IntentHash == intent && receipt.Cancelled == (presend || lost) &&
            receipt.Evidence == (presend ? DispatchEvidence.NotDispatched : lost ? DispatchEvidence.PossiblyDispatched :
                denied ? DispatchEvidence.Rejected : DispatchEvidence.Applied) &&
            receipt.Status == (presend || lost ? null : denied ? SecretStatus.Denied : SecretStatus.Success) &&
            ingress.Length == (presend ? 0 : 1) &&
            ingress.All(i => i.Actor == Root.Authorities.Actor(Root.Boundary) &&
                i.Method == (Root.Operation == TemplatePrincipalContract.Create ? "POST" : "PATCH") &&
                i.Path == path && i.IntentHash == intent && i.Authorized == !denied) &&
            commits.All(c => ingress.Any(i => i.Request == c.Request && i.Authorized) &&
                c.Template == Issued.TemplateId && c.PreviousRevision == (Root.Operation == TemplatePrincipalContract.Create ? "" : baselineRevision) &&
                TemplatePrincipalContract.Text(c.Revision) && c.Revision != baselineRevision) &&
            commits.Select(c => c.Revision).Distinct().Count() <= 1 &&
            commits.Select(c => c.ConfigurationHash).Distinct().Count() <= 1 &&
            commits.Select(c => c.Field).Distinct().Count() == commits.Length, "effect-mismatch");
        string selectedField = TemplatePrincipalContract.Field(Root.Variant);
        string[] fields = Root.Variant.EndsWith(".omitted", StringComparison.Ordinal) ?
            ["roles", .. TemplatePrincipalContract.Fields.Where(f => f != selectedField)] :
            ["roles", .. TemplatePrincipalContract.Fields];
        TemplatePrincipalContract.Require(commits.All(c => fields.Contains(c.Field)) && commits.Length <= fields.Length,
            "effect-mismatch");
        Outcome = commits.Length == 0 ? TemplatePrincipalOutcome.NonApplied :
            commits.Length == fields.Length ? TemplatePrincipalOutcome.Applied : TemplatePrincipalOutcome.Partial;
        TemplatePrincipalContract.Require((!presend && !denied || Outcome == TemplatePrincipalOutcome.NonApplied) &&
            (lost || presend || denied || Outcome == TemplatePrincipalOutcome.Applied), "effect-mismatch");
        failed = false;
    }
    private async ValueTask<TemplatePrincipalPacket> StepAsync(TemplatePrincipalStep step, SecretMaterial? capability,
        TemplatePrincipalReceipt? receipt, CancellationToken token)
    {
        TemplatePrincipalContract.Require(!failed && !busy && !closed && (int)step == stage);
        busy = failed = true; stage++;
        using var deadline = CancellationTokenSource.CreateLinkedTokenSource(token);
        deadline.CancelAfter(TimeSpan.FromSeconds(seconds));
        TemplatePrincipalPacket? packet = null;
        try
        {
            packet = await source.StepAsync(Root, step, capability, receipt, deadline.Token);
            var owner = Verify(packet, step);
            TemplatePrincipalContract.Require(owner.CollisionChecked && owner.PreEnrolled && owner.Exclusive &&
                owner.PendingIssuers == 0 && owner.PendingDispatches == 0);
            if (borrowed is null) borrowed = owner.Borrowed;
            TemplatePrincipalContract.Require(TemplatePrincipalContract.Hash(borrowed) == TemplatePrincipalContract.Hash(owner.Borrowed));
            Inventory(owner.Enrolled);
            TemplatePrincipalContract.Require(enrolled.All(owner.Enrolled.Contains));
            enrolled = owner.Enrolled;
            if (step == TemplatePrincipalStep.Open)
            {
                Issued = owner.Issued ?? throw new SecretKit.TestFixtures.NativeCaseFailureException("observer-unavailable");
                copies.Add(Issued);
                TemplatePrincipalContract.Require(Issued.Users.Length == 3 && Issued.Users.Select(c => c.Principal).Distinct().Count() == 3 &&
                    Issued.Users.All(c => c.Kind == "user" && c.Hash == TemplatePrincipalContract.HashBytes(c.Bytes)) &&
                    new[] { Issued.BeforeManaged, Issued.AfterManaged }.Concat(Issued.Users.Select(c => c.Principal))
                        .Distinct().Count() == 5 &&
                    new[] { Issued.BeforeManaged, Issued.AfterManaged }.Concat(Issued.Users.Select(c => c.Principal))
                        .All(p => !Root.Authorities.All.Contains(p)) &&
                    Issued.ValueHash == TemplatePrincipalContract.HashBytes(Issued.Value));
                credentials.AddRange(Issued.Users);
            }
            else if (owner.Issued is not null) { copies.Add(owner.Issued); }
            failed = false;
            return packet;
        }
        catch { packet?.Owner.Payload.Content.Issued?.Erase(); throw; }
        finally { busy = false; }
    }
    private TemplatePrincipalOwner Verify(TemplatePrincipalPacket p, TemplatePrincipalStep step)
    {
        var owner = verifier.Verify(p.Owner, TemplatePrincipalJournal.Ownership, step);
        verifier.Verify(p.Ingress, TemplatePrincipalJournal.Ingress, step);
        verifier.Verify(p.Templates, TemplatePrincipalJournal.Template, step);
        verifier.Verify(p.Issuers, TemplatePrincipalJournal.Issuer, step);
        verifier.Verify(p.Memberships, TemplatePrincipalJournal.Membership, step);
        verifier.Verify(p.Access, TemplatePrincipalJournal.Access, step);
        return owner;
    }
    private void Inventory(TemplatePrincipalResource[] resources) =>
        TemplatePrincipalContract.Require(resources.All(r => r.Root == Root.Id && r.Nonce == Root.Nonce &&
            TemplatePrincipalContract.Text(r.Id) && r.Kind is "user" or "organization-membership" or "credential" or "group" or "group-member" or
                "template" or "project" or "environment" or "managed" or "auth" or "membership" or "role" or "secret") &&
            resources.Select(r => (r.Kind, r.Id)).Distinct().Count() == resources.Length);
    public async ValueTask DisposeAsync()
    {
        if (closed) return;
        closed = true;
        using var deadline = new CancellationTokenSource(TimeSpan.FromSeconds(seconds));
        try
        {
            var packet = await source.StepAsync(Root, TemplatePrincipalStep.Close, null, null, deadline.Token);
            var owner = Verify(packet, TemplatePrincipalStep.Close);
            packet.Owner.Payload.Content.Issued?.Erase();
            Inventory(owner.Enrolled);
            TemplatePrincipalContract.Require(owner.Terminal && owner.PrivateReleased && owner.PendingIssuers == 0 &&
                owner.PendingDispatches == 0 && owner.Registrations == 0 && owner.Remaining.Length == 0 &&
                enrolled.All(owner.Enrolled.Contains) && (borrowed is null ||
                    TemplatePrincipalContract.Hash(owner.Borrowed) == TemplatePrincipalContract.Hash(borrowed)), "cleanup-incomplete");
        }
        catch (Exception) { throw new SecretKit.TestFixtures.NativeCaseFailureException("cleanup-incomplete"); }
        finally
        {
            foreach (var c in credentials) c.Erase();
            foreach (var copy in copies) copy.Erase();
            verifier.Dispose();
        }
    }
    public override string ToString() => "[TemplatePrincipalTrial]";
}
