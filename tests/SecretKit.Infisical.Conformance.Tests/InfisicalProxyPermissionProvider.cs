using System.Text.Json;
using System.Text.Json.Nodes;

namespace SecretKit.Infisical.Conformance.Tests;

internal sealed partial class InfisicalProxyPermissionFixture
{
    private (int, object) TargetAction(ProxyPermissionCredential actor, string method, string path, JsonElement body, byte[] bytes)
    {
        string plain = path.Split('?')[0]; string[] parts = plain.Split('/', StringSplitOptions.RemoveEmptyEntries);
        if (parts.Length < 3 || parts[2] != "proxied-services") return (404, new { });
        if (actor.Principal == Authorities.Observer && method == "GET")
        {
            var query = new Uri(Origin, path).Query.TrimStart('?').Split('&', StringSplitOptions.RemoveEmptyEntries)
                .Select(p => p.Split('=', 2)).ToDictionary(p => Uri.UnescapeDataString(p[0]), p => Uri.UnescapeDataString(p[1]));
            if (parts.Length == 3)
            {
                var selected = states.Values.Where(s => s.Project == query["projectId"] && s.Environment == query["environment"] && s.SecretPath == query["secretPath"]);
                if (Fault == "false-inventory") selected = selected.Skip(1);
                return (200, new { projectSlug = "closed-project", services = selected.Select(s => TargetRow(s, true)).ToArray() });
            }
            var state = parts[3] == "slug" ? states.Values.SingleOrDefault(s => s.Name == Uri.UnescapeDataString(parts[4]) &&
                s.Project == query["projectId"] && s.Environment == query["environment"] && s.SecretPath == query["secretPath"]) :
                states.Values.SingleOrDefault(s => s.Target == parts[3]);
            if (state is null) return (404, new { });
            var value = TargetRow(state, true);
            if (Fault == "false-readback") value["hostPattern"] = "foreign.example.invalid";
            return (200, new { service = value });
        }
        if (window is not ("before" or "after")) return (403, new { });
        var action = method switch
        {
            "GET" => ProxyPermissionAction.Read,
            "POST" => ProxyPermissionAction.Create,
            "PATCH" => ProxyPermissionAction.Edit,
            "DELETE" => ProxyPermissionAction.Delete,
            _ => throw new InvalidOperationException()
        };
        var row = action == ProxyPermissionAction.Create ? plan!.Rows.SingleOrDefault(r => r.Name == body.GetProperty("name").GetString() &&
            Id(r.Project) == body.GetProperty("projectId").GetString()) : plan!.Rows.SingleOrDefault(r => Id(r.Target) == parts.Last());
        if (row is null) return (404, new { });
        string project = Id(row.Project), org = Id(row.Organization);
        var effective = project == Id(ProxyPermissionPlan.CopyProject) && copied ? copiedPolicy : policy;
        string wire = ProxyPermissionContract.Wire(action);
        bool allowed = assigned && effective is not null && effective.Subject == "proxied-services" && effective.Actor == actor.Principal &&
            effective.Kind == actor.Kind && actor.Organization == org && effective.Organization == org && effective.Project == project &&
            effective.Actions.Contains(wire) && effective.Names.SequenceEqual([row.Environment, row.SecretPath]) &&
            Joins().Any(j => j.Principal == actor.Principal && j.Kind == (actor.Kind == MemberPermissionActorKind.User ? "user" : "machine") &&
                j.Organization == org && j.Project == project && j.Assigned && j.RoleId == effective.Resource && j.RoleSlug == effective.Role && j.Active && j.Status == "accepted");
        if (Fault == "action-leak" && revision == "policy-2" && actor.Principal == actors[0].Principal && project == Id(copied ? ProxyPermissionPlan.CopyProject : ProxyPermissionPlan.Project)) allowed = true;
        if (Fault == "scope-leak" && revision == "policy-2" && actor.Principal == actors[0].Principal && policy?.Actions.Contains(wire) == true) allowed = true;
        string request = Guid.NewGuid().ToString("N"); var recorded = Fault == "wrong-actor" ? actor with { Principal = Authorities.Observer } : actor;
        if (Fault == "wrong-credential") recorded = recorded with { Hash = "wrong" };
        Record(request, recorded, method, path, bytes, "", allowed, "action");
        var previous = states.GetValueOrDefault(row.Key); object response = new { };
        if (allowed)
        {
            switch (action)
            {
                case ProxyPermissionAction.Create:
                    CommitCreation(row.Target, request);
                    var binding = storageBindings.Single(b => b.Intent == row.Target);
                    Store(row, body, 1, request, binding.Commit, ProxyPermissionContract.RawHash(bytes));
                    response = new { service = TargetRow(states[row.Key], false) }; break;
                case ProxyPermissionAction.Edit:
                    Store(row, body, 2, request, Guid.NewGuid().ToString("N"), ProxyPermissionContract.RawHash(bytes));
                    response = new { service = TargetRow(states[row.Key], false) }; break;
                case ProxyPermissionAction.Delete:
                    response = new { service = TargetRow(previous!, false, false) };
                    Retire(previous!, request, Guid.NewGuid().ToString("N"), ProxyPermissionContract.RawHash(bytes));
                    states.Remove(row.Key); configurations.Remove(row.Key); resources.Remove(row.Target); break;
                case ProxyPermissionAction.Read:
                    response = new { service = TargetRow(previous!, true) }; break;
            }
            if (states.TryGetValue(row.Key, out var wrong))
                states[row.Key] = Fault switch
                {
                    "wrong-service" => wrong with { Target = Guid.NewGuid().ToString() },
                    "wrong-destination" => wrong with { Host = "foreign.example.invalid" },
                    "wrong-environment" => wrong with { Environment = "foreign" },
                    "wrong-path" => wrong with { SecretPath = "/foreign" },
                    "wrong-enabled" => wrong with { Enabled = !wrong.Enabled },
                    "wrong-protected-configuration" => wrong with { First = wrong.First with { Fingerprint = "foreign" } },
                    "false-persistence" when previous is not null => previous,
                    _ => wrong
                };
            if (Fault == "false-persistence" && action == ProxyPermissionAction.Create) states.Remove(row.Key);
            if (Fault == "self-policy-overwrite" && policy is not null) policy = policy with { Actions = ["delete"] };
        }
        decisions.Add(new(request, recorded.Principal, recorded.Kind, recorded.Id, recorded.Hash,
            Fault == "wrong-organization" ? Id(ProxyPermissionPlan.OtherOrganization) : org,
            Fault == "wrong-project" ? Id(ProxyPermissionPlan.OtherProject) : project, Id(row.Target), revision, action, allowed));
        changes.Add(new(request, row.Key, previous, states.GetValueOrDefault(row.Key)));
        return (allowed ? 200 : 403, response);
    }
    private JsonElement BootstrapBody(ProxyPermissionRow row) => JsonSerializer.SerializeToElement(new
    {
        projectId = Id(row.Project),
        environment = row.Environment,
        secretPath = row.SecretPath,
        name = row.Name,
        hostPattern = "api-v1.example.invalid",
        isEnabled = true,
        credentials = Enumerable.Range(0, 2).Select(slot => new
        {
            role = "credential-substitution",
            secretKey = "TARGET_" + slot + "_V1",
            placeholderKey = "TOKEN_" + slot,
            placeholderValue = ProxyPermissionContract.Hash(new { root!.Id, root.Nonce, row.Key, version = 1, slot }),
            substitutionSurfaces = new[] { "header", "query" }
        }).ToArray()
    });
    private void Store(ProxyPermissionRow row, JsonElement body, int version, string request, string commit, string inputHash)
    {
        var previous = states.GetValueOrDefault(row.Key); var inputs = body.GetProperty("credentials").EnumerateArray().ToArray();
        ProxyPermissionCredentialState Credential(int slot)
        {
            var c = inputs[slot];
            string fingerprint = ProxyPermissionContract.Hash(new
            {
                Role = c.GetProperty("role").GetString(),
                SecretKey = c.GetProperty("secretKey").GetString(),
                PlaceholderKey = c.GetProperty("placeholderKey").GetString(),
                PlaceholderHash = ProxyPermissionContract.Hash(c.GetProperty("placeholderValue").GetString()),
                Surfaces = string.Join(",", c.GetProperty("substitutionSurfaces").EnumerateArray().Select(x => x.GetString())),
                DynamicSecretName = (string?)null,
                DynamicSecretField = (string?)null,
                HeaderName = (string?)null,
                HeaderPrefix = (string?)null,
                HeaderPurpose = (string?)null
            });
            return new(slot, retainIds && previous is not null ? previous.Credentials[slot].Id : Guid.NewGuid().ToString(), Id(row.Target), fingerprint);
        }
        var next = new ProxyPermissionState(row.Key, Id(row.Target), Id(row.Organization), Id(row.Project), body.GetProperty("name").GetString()!,
            body.GetProperty("hostPattern").GetString()!, version == 1 ? body.GetProperty("environment").GetString()! : previous!.Environment,
            version == 1 ? body.GetProperty("secretPath").GetString()! : previous!.SecretPath, Id(row.Folder), body.GetProperty("isEnabled").GetBoolean(), version, Credential(0), Credential(1));
        states[row.Key] = next; configurations[row.Key] = body.Clone();
        collectionDispatches.Add(new(root!.Id, root.Nonce, request, next.Target, inputHash, window.Length == 0 ? "setup" : "action"));
        collectionHistory.Add(new(root.Id, root.Nonce, request, commit, inputHash, previous, next));
        collections.Persist(root, request, commit, inputHash, row.Key, next.Organization, next.Project, next.Environment, next.SecretPath,
            JsonSerializer.SerializeToElement(TargetRow(next, false)), version);
    }
    private void Retire(ProxyPermissionState previous, string request, string commit, string inputHash)
    {
        collectionDispatches.Add(new(root!.Id, root.Nonce, request, previous.Target, inputHash, closing ? "close" : "action"));
        collectionHistory.Add(new(root.Id, root.Nonce, request, commit, inputHash, previous, null));
        collections.Retire(root, previous.Target, request, commit, inputHash);
    }
    private JsonObject TargetRow(ProxyPermissionState state, bool access, bool credentials = true)
    {
        var value = new JsonObject
        {
            ["id"] = state.Target,
            ["name"] = state.Name,
            ["hostPattern"] = state.Host,
            ["folderId"] = state.Folder,
            ["isEnabled"] = state.Enabled,
            ["createdAt"] = "2026-01-01T00:00:00Z",
            ["updatedAt"] = "2026-01-01T00:00:01Z"
        };
        if (access) value["canProxy"] = false;
        if (credentials)
        {
            var array = new JsonArray(); var inputs = configurations[state.Row].GetProperty("credentials").EnumerateArray().ToArray();
            foreach (var credential in state.Credentials)
            {
                var c = JsonNode.Parse(inputs[credential.Slot].GetRawText())!.AsObject();
                c["id"] = credential.Id; c["serviceId"] = credential.ServiceId;
                foreach (string field in new[] { "dynamicSecretName", "dynamicSecretField", "headerName", "headerPrefix", "headerPurpose" }) c[field] = null;
                if (access) c["callerCanLease"] = false;
                array.Add(c);
            }
            value["credentials"] = array;
        }
        return value;
    }
}
