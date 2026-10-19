using SecretKit.Infisical.Management;

namespace SecretKit.Infisical.Conformance.Tests;

// A sealed page is not a publication fence. The publisher's contiguous census
// closes admitted producer work; independent storage must contain its entire image.
// The seed commit and ingress authenticate the parent, including SDK input bytes.
// Neither a timestamp match nor AuditEntry's deliberately absent metadata can do so.
internal sealed class AuditPermissionPublicationProof(AuditPermissionRoot root, AuditPermissionPlan plan)
{
    private AuditPermissionEvent[] published = [];
    private AuditPermissionState[] historical = [];
    private AuditPermissionIngress[] ingress = [];
    private AuditPermissionSeedCommit[] produced = [];
    private AuditPermissionCredential[] credentials = [];
    internal void Check(AuditPermissionPacket packet, bool fenced)
    {
        var p = packet.Publisher.Payload.Content; var s = packet.Storage.Payload.Content;
        var requests = packet.Ingress.Payload.Content; var issuedCredentials = packet.Issuer.Payload.Content.History;
        AuditPermissionContract.Require(issuedCredentials.Length >= credentials.Length && issuedCredentials.Take(credentials.Length).SequenceEqual(credentials) &&
            issuedCredentials.Select(c => c.Id).Distinct().Count() == issuedCredentials.Length &&
            packet.Issuer.Payload.Content.Credentials.All(issuedCredentials.Contains));
        AuditPermissionContract.Require(requests.Length >= ingress.Length && requests.Take(ingress.Length).SequenceEqual(ingress) &&
            requests.Select(r => r.Request).Distinct().Count() == requests.Length &&
            s.Seeds.Length >= produced.Length && s.Seeds.Take(produced.Length).SequenceEqual(produced) &&
            s.Seeds.Select(c => c.Seed).Distinct().Count() == s.Seeds.Length && s.Seeds.Select(c => c.Request).Distinct().Count() == s.Seeds.Length &&
            p.Events.Length >= published.Length && p.Events.Take(published.Length).SequenceEqual(published) &&
            s.Inventory.Length >= historical.Length && s.Inventory.Take(historical.Length).SequenceEqual(historical));
        AuditPermissionContract.Require(requests.All(r => issuedCredentials.Any(c => c.Principal == r.Actor && c.Kind == r.Kind &&
            c.Organization == r.Organization && c.Hash == r.CredentialHash)));
        // Even root-only recovery must account for every admitted successful seed.
        // A publisher and storage snapshot cannot jointly hide an ingress request.
        AuditPermissionContract.Require(requests.Count(r => r.Phase == "seed" && r.Authorized) == s.Seeds.Length &&
            requests.Where(r => r.Phase == "seed" && r.Authorized).All(r => s.Seeds.Any(c => c.Request == r.Request)) &&
            s.Bindings.Count(b => b.Kind == "seed-role") == s.Seeds.Length);
        var issued = new AuditPermissionIssued([], s.Bindings);
        foreach (var commit in s.Seeds)
        {
            var seed = plan.Seeds.SingleOrDefault(v => v.Key == commit.Seed);
            AuditPermissionContract.Require(seed is not null);
            using var expected = AuditPermissionClient.SeedRequest(root, issued, seed!);
            var request = requests.SingleOrDefault(r => r.Request == commit.Request);
            var binding = s.Bindings.SingleOrDefault(b => b.Intent == seed!.Target);
            AuditPermissionContract.Require(request is not null && binding is not null && binding.Request == commit.Request &&
                binding.CanonicalId == commit.Target && request.Phase == "seed" && request.Actor == root.Authorities.Setup &&
                request.Kind == MemberPermissionActorKind.Machine && request.Organization == root.Organization && request.Authorized &&
                request.Method == "POST" && request.Path == AuditPermissionClient.SeedPath(root, issued, seed!) &&
                request.IntentHash == expected.Target.SecondaryId && request.BodyHash == expected.Target.SecondaryId &&
                commit.InputHash == expected.Target.SecondaryId && commit.Organization == issued.Id(seed!.Organization) &&
                commit.Project == issued.Id(seed.Project) && request.At >= root.From && request.At < root.Until);
        }
        AuditPermissionContract.Require(p.Events.Select(e => e.Event).Distinct().Count() == p.Events.Length &&
            p.Events.Select(e => e.Seed).Distinct().Count() == p.Events.Length && p.Events.Select(e => e.ParentRequest).Distinct().Count() == p.Events.Length &&
            p.Events.Select(e => e.Ordinal).SequenceEqual(Enumerable.Range(1, p.Events.Length).Select(i => (long)i)) &&
            p.Watermark == p.Events.Length && p.Count == p.Events.Length && p.CensusHash == AuditPermissionContract.Hash(p.Events) &&
            s.Inventory.Select(r => r.Id).Distinct().Count() == s.Inventory.Length && s.Inventory.Select(r => r.Publication).Distinct().Count() == s.Inventory.Length &&
            s.CensusHash == AuditPermissionContract.Hash(s.Inventory) && s.Inventory.Length == p.Events.Length);
        foreach (var e in p.Events)
        {
            var commit = s.Seeds.SingleOrDefault(c => c.Seed == e.Seed);
            var request = requests.SingleOrDefault(r => r.Request == e.ParentRequest);
            var seed = plan.Seeds.SingleOrDefault(v => v.Key == e.Seed);
            var credential = issuedCredentials.SingleOrDefault(c => c.Id == e.CredentialId);
            AuditPermissionContract.Require(commit is not null && request is not null && seed is not null &&
                e.ParentRequest == commit.Request && e.ProducerCommitHash == AuditPermissionContract.Hash(commit) &&
                e.Actor == request.Actor && e.Kind == request.Kind && e.CredentialHash == request.CredentialHash &&
                (credential is not null && credential.Principal == e.Actor && credential.Kind == e.Kind && credential.Hash == e.CredentialHash && credential.Organization == e.Organization) &&
                e.Organization == commit.Organization && e.Project == commit.Project && e.Target == commit.Target &&
                e.InputHash == commit.InputHash && e.At == request.At && e.At >= root.From && e.At < root.Until &&
                e.EventClass == AuditEventClass.Management && e.EventType == plan.EventType);
            var binding = s.Bindings.SingleOrDefault(b => b.Intent == seed!.Audit);
            var row = s.Inventory.SingleOrDefault(r => r.Publication == e.Event);
            AuditPermissionContract.Require(binding is not null && row is not null && binding.Request == e.Event && binding.CanonicalId == row.Id &&
                row == new AuditPermissionState(binding.CanonicalId, e.Event, e.ParentRequest, AuditPermissionContract.Hash(e), e.Organization, e.Project,
                    e.Actor, e.Kind, e.CredentialHash, e.EventType, e.EventClass, e.At, e.InputHash, e.Target, root.RetainUntil));
        }
        if (fenced)
            AuditPermissionContract.Require(p.ProducerFence && p.PublicationFence && p.PendingProducers == 0 && p.PendingPublications == 0 &&
                packet.Owner.Payload.Content.ProducerFence && packet.Owner.Payload.Content.PublicationFence &&
                p.Events.Length == s.Seeds.Length && s.Bindings.Count(b => b.Kind == "audit-row") == s.Inventory.Length);
        credentials = issuedCredentials.ToArray(); ingress = requests.ToArray(); produced = s.Seeds.ToArray(); published = p.Events.ToArray(); historical = s.Inventory.ToArray();
    }
}
