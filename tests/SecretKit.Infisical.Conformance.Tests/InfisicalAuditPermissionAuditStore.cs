using System.Globalization;
using System.Security.Cryptography;
using System.Text.Json;
using System.Text.Json.Nodes;
using SecretKit.Infisical.Management;

namespace SecretKit.Infisical.Conformance.Tests;

internal sealed partial class InfisicalAuditPermissionFixture
{
    private (int, object) Seed(AuditPermissionCredential actor, string method, string path, JsonElement body, byte[] bytes)
    {
        if (producerFence || !window.StartsWith("seed-", StringComparison.Ordinal) || method != "POST" || actor.Principal != Authorities.Setup ||
            actor.Kind != MemberPermissionActorKind.Machine || actor.Organization != Organization || !body.TryGetProperty("slug", out var slug)) return (403, new { });
        var seed = plan!.Seeds.SingleOrDefault(s => s.Slug == slug.GetString());
        string selected = window == "seed-before" ? "before" : copied ? "copy" : "after";
        if (seed is null || seed.Window != selected || seedCommits.Any(s => s.Seed == seed.Key) ||
            path != (seed.Project.Length == 0 ? "/api/v1/organization/roles" : "/api/v1/projects/" + Id(seed.Project) + "/roles") ||
            body.GetProperty("name").GetString() != seed.Name || body.GetProperty("description").GetString() != "closed-seed" || body.GetProperty("permissions").GetArrayLength() != 0) return (403, new { });
        string request = Guid.NewGuid().ToString("N"), input = AuditPermissionContract.RawHash(bytes);
        string target = CommitCreation(seed.Target, request);
        Record(request, actor, method, path, bytes, input, true, "seed");
        var commit = new AuditPermissionSeedCommit(seed.Key, request, target, Id(seed.Organization), Id(seed.Project), input);
        seedCommits.Add(commit); outbox.Enqueue((commit, actor, ingress[^1].At));
        if (Fault == "delayed-publisher" && publishing is null) publishing = PublishAsync();
        var role = new Dictionary<string, object?>
        {
            ["id"] = target,
            ["name"] = seed.Name,
            ["slug"] = seed.Slug,
            ["description"] = "closed-seed",
            ["permissions"] = Array.Empty<object>(),
            [seed.Project.Length == 0 ? "orgId" : "projectId"] = seed.Project.Length == 0 ? Organization : Id(seed.Project),
            ["createdAt"] = ingress[^1].At.ToString("O"),
            ["updatedAt"] = ingress[^1].At.ToString("O")
        };
        return (200, new { role });
    }
    private async Task PublishAsync()
    {
        if (Fault == "delayed-publisher") { PublisherEntered.TrySetResult(); await PublisherRelease.Task.WaitAsync(shutdown.Token); }
        lock (gate)
        {
            while (outbox.TryDequeue(out var work))
            {
                var c = work.Commit; var a = work.Actor; var seed = plan!.Seeds.Single(s => s.Key == c.Seed);
                var e = new AuditPermissionEvent(c.Seed, Guid.NewGuid().ToString("N"), publications.Count + 1, c.Request, AuditPermissionContract.Hash(c),
                    a.Principal, a.Kind, a.Id, a.Hash, c.Organization, c.Project,
                    seed.Project.Length == 0 ? "create-org-role" : "create-project-role", AuditEventClass.Management, work.At, c.InputHash, c.Target);
                // Publication's event ID is NOT a native storage ID. The independent
                // issuance/storage join is append-only and observes the publication.
                publications.Add(e);
                string canonical = CommitCreation(seed.Audit, e.Event, admitted: true);
                states.Add(new(canonical, e.Event, e.ParentRequest, AuditPermissionContract.Hash(e), e.Organization, e.Project,
                    e.Actor, e.Kind, e.CredentialHash, e.EventType, e.EventClass, e.At, e.InputHash, e.Target, root!.RetainUntil));
            }
            publicationFence = producerFence;
        }
    }
    internal async Task FencePublicationAsync()
    {
        Task pending;
        lock (gate) { producerFence = true; publishing ??= PublishAsync(); pending = publishing; }
        await pending;
        lock (gate) { publicationFence = outbox.Count == 0; publishing = null; }
        await Task.WhenAll(connections);
    }
    private (int, object) ReadAudit(AuditPermissionCredential actor, Uri uri, byte[] bytes)
    {
        if (window is not ("before" or "after") || !producerFence || !publicationFence) return (403, new { });
        var query = uri.Query[1..].Split('&').Select(part => part.Split('=', 2)).ToDictionary(p => Uri.UnescapeDataString(p[0]), p => Uri.UnescapeDataString(p[1]));
        string project = query.GetValueOrDefault("projectId") ?? "";
        int offset = int.Parse(query["offset"], CultureInfo.InvariantCulture), limit = int.Parse(query["limit"], CultureInfo.InvariantCulture);
        var from = DateTimeOffset.Parse(query["startDate"], CultureInfo.InvariantCulture); var until = DateTimeOffset.Parse(query["endDate"], CultureInfo.InvariantCulture);
        if (limit is < 1 or > 1000 || offset < 0 || from != root!.From || until != root.Until || query["actor"] != Authorities.Setup ||
            query["actorType"] != "identity" || query["eventClass"] != "management" || query["eventType"] != (root.ScopeProfile == AuditPermissionScope.Organization ? "create-org-role" : "create-project-role")) return (400, new { });
        var effective = project == Id(AuditPermissionPlan.CopyProject) && copied ? copiedPolicy : policy;
        bool allowed = assigned && effective is not null && effective.Actor == actor.Principal && effective.Kind == actor.Kind &&
            effective.Organization == actor.Organization && effective.Project == project && effective.Subject == "audit-logs" &&
            effective.Actions.SequenceEqual(new[] { "read" }) && effective.Names.Length == 0 &&
            Joins().Any(j => j.Principal == actor.Principal && j.Kind == (actor.Kind == MemberPermissionActorKind.User ? "user" : "machine") &&
                j.Organization == actor.Organization && j.Project == project && j.Assigned && j.RoleId == effective.Resource && j.RoleSlug == effective.Role && j.Active && j.Status == "accepted");
        if (Fault == "scope-leak" && revision == "policy-2" && actor.Principal == actors[0].Principal) allowed = true;
        if (Fault == "actor-leak" && revision == "policy-2" && actor.Organization == Organization) allowed = true;
        string request = Guid.NewGuid().ToString("N");
        string intent = WireHash(new { query = uri.Query[1..], classArray = true, typeArray = true });
        var recorded = Fault == "wrong-actor" ? actor with { Principal = Authorities.Observer } : actor;
        if (Fault == "wrong-credential") recorded = recorded with { Hash = "foreign-hash" };
        Record(request, recorded, "GET", Fault == "wrong-read-path" ? "/unrelated?" + uri.Query[1..] : uri.PathAndQuery, bytes, intent, allowed, "read");
        var matches = states.Where(s => s.Organization == actor.Organization && (project.Length == 0 || s.Project == project) &&
            s.At >= from && s.At < until && s.Actor == query["actor"] && s.EventType == query["eventType"] && s.EventClass == AuditEventClass.Management).ToArray();
        if (Fault == "reverse-page-order") Array.Reverse(matches);
        var selected = allowed ? matches.Skip(offset).Take(limit).ToArray() : [];
        if (allowed && Fault == "omitted-page") selected = selected.Take(1).ToArray();
        if (allowed && Fault == "duplicate-page" && selected.Length > 0) selected = Enumerable.Repeat(selected[0], selected.Length).ToArray();
        if (allowed && Fault == "fabricated-page" && selected.Length > 0) selected[0] = selected[0] with { Id = Guid.NewGuid().ToString() };
        decisions.Add(new(request, recorded.Principal, recorded.Kind, recorded.Id, recorded.Hash, actor.Organization, project, revision, intent, offset, limit, selected.Select(s => s.Id).ToArray(), allowed));
        if (!allowed) return (403, new { });
        var rows = selected.Select(AuditJson).ToArray();
        if (Fault == "partial-invalid-page" && rows.Length > 0) rows[0]["orgId"] = Guid.NewGuid().ToString();
        if (Fault == "late-page" && rows.Length > 0) rows[0]["createdAt"] = root.Until.AddSeconds(1).ToString("O");
        if (Fault == "overfull-page" && rows.Length > 0) rows = [.. rows, rows[0]];
        return (200, new { auditLogs = rows });
    }
    private static JsonObject AuditJson(AuditPermissionState s) => new()
    {
        ["id"] = s.Id,
        ["orgId"] = s.Organization,
        ["projectId"] = s.Project.Length == 0 ? null : s.Project,
        ["createdAt"] = s.At.ToString("O"),
        ["updatedAt"] = s.At.ToString("O"),
        ["expiresAt"] = s.ExpiresAt.ToString("O"),
        ["actor"] = new JsonObject { ["type"] = s.Kind == MemberPermissionActorKind.Machine ? "identity" : "user", ["metadata"] = new JsonObject { ["id"] = s.Actor } },
        ["event"] = new JsonObject { ["type"] = s.EventType, ["class"] = "management", ["metadata"] = new JsonObject { ["roleId"] = s.Target } },
        ["ipAddress"] = "127.0.0.1",
        ["userAgent"] = "owned-fixture",
        ["userAgentType"] = "other",
        ["projectName"] = null
    };
    internal async Task SealAndDrainAsync()
    {
        lock (gate) { closing = true; settled = true; armed = false; CloseEntered.TrySetResult(); }
        if (delayed is not null) await delayed;
        await FencePublicationAsync();
    }
    internal Task DrainAsync() => Task.WhenAll(connections);
    public async ValueTask DisposeAsync()
    {
        OpenRelease.TrySetResult(); IssuerRelease.TrySetResult(); PublisherRelease.TrySetResult();
        if (delayed is not null) await delayed;
        if (publishing is not null) await publishing;
        shutdown.Cancel(); listener.Stop();
        try { await accept; } catch (System.Net.Sockets.SocketException) when (shutdown.IsCancellationRequested) { }
        await Task.WhenAll(connections);
        foreach (var bytes in privateBuffers) CryptographicOperations.ZeroMemory(bytes);
        ownedKey?.Dispose(); Source.Dispose(); foreach (var writer in writers.Values) writer.Dispose(); shutdown.Dispose();
    }
}
