using SecretKit.Core;
using SecretKit.Infisical.Management;
using SecretKit.TestFixtures;

namespace SecretKit.Infisical.Conformance.Tests;

internal static class ProxyPermissionClient
{
    internal static string Method(ProxyPermissionAction action) => action switch
    { ProxyPermissionAction.Read => "GET", ProxyPermissionAction.Create => "POST", ProxyPermissionAction.Edit => "PATCH", ProxyPermissionAction.Delete => "DELETE", _ => throw new NativeCaseFailureException("observer-unavailable") };
    internal static string Path(ProxyPermissionRoot root, ProxyPermissionPlan plan, ProxyPermissionIssued issued, ProxyPermissionRow row) =>
        "/api/v1/proxied-services" + (row.Action == ProxyPermissionAction.Create ? "" : "/" + issued.Id(row.Target));
    internal static ManagementRequest<ProxiedServiceSummary> Request(ProxyPermissionRoot root, ProxyPermissionIssued issued, ProxyPermissionRow row)
    {
        string org = issued.Id(row.Organization), project = issued.Id(row.Project), id = issued.Id(row.Target);
        if (row.Action == ProxyPermissionAction.Read) return ProxiedServiceAdministrationOperations.Get(org, project, id);
        if (row.Action == ProxyPermissionAction.Delete) return ProxiedServiceAdministrationOperations.Delete(org, project, id);
        ProxyPermissionContract.Require(row.Action is ProxyPermissionAction.Create or ProxyPermissionAction.Edit, "observer-unavailable");
        int version = row.Action == ProxyPermissionAction.Edit ? 2 : 1;
        using var first = SecretMaterial.FromText(ProxyPermissionPlan.Placeholder(root, row, version, 0));
        using var second = SecretMaterial.FromText(ProxyPermissionPlan.Placeholder(root, row, version, 1));
        using var a = new ProxiedServiceCredentialInput(ProxiedServiceCredentialRole.CredentialSubstitution,
            secretKey: "TARGET_0_V" + version, placeholderKey: "TOKEN_0", placeholderValue: first,
            substitutionSurfaces: [ProxiedServiceSubstitutionSurface.Header, ProxiedServiceSubstitutionSurface.Query]);
        using var b = new ProxiedServiceCredentialInput(ProxiedServiceCredentialRole.CredentialSubstitution,
            secretKey: "TARGET_1_V" + version, placeholderKey: "TOKEN_1", placeholderValue: second,
            substitutionSurfaces: [ProxiedServiceSubstitutionSurface.Header, ProxiedServiceSubstitutionSurface.Query]);
        if (version == 1)
        {
            using var creation = new ProxiedServiceCreation(project, row.Environment, row.Name, ProxyPermissionPlan.Host(1), [a, b], row.SecretPath, true);
            return ProxiedServiceAdministrationOperations.Create(org, creation);
        }
        using var update = new ProxiedServiceUpdate(row.Name + "-v2", ProxyPermissionPlan.Host(2), false, [a, b]);
        return ProxiedServiceAdministrationOperations.Update(org, project, id, update);
    }
    internal static async ValueTask<ProxyPermissionAttempt> ExecuteAsync(NativeEnvironment env, ProxyPermissionRoot root,
        ProxyPermissionPlan plan, ProxyPermissionIssued issued, ProxyPermissionRow row, CancellationToken token)
    {
        var actor = issued.Actors[row.Actor];
        using var tokens = actor.Owned ? new MemberPermissionTokens(actor.Credential) :
            new MemberPermissionTokens(env.Tokens(actor.Principal == root.Authorities.Denied ? NativeIdentityRole.Denied : NativeIdentityRole.Runtime));
        var client = env.CreateManagementClient(); using var request = Request(root, issued, row);
        var authority = new ManagementAuthority(client.Authority, tokens, issued.Id(row.Organization), request.Target.ProjectId);
        var receipt = request.IsMutation ? client.CreateReceipt(request) : null;
        var result = await client.ExecuteAsync(request, authority, authority.IssueGrant(request.OperationId, request.Target), receipt, token);
        ProxyPermissionState? value = null;
        if (result.IsSuccess)
        {
            using var summary = result.Value;
            if (row.Action == ProxyPermissionAction.Delete)
                ProxyPermissionContract.Require(summary.Id == issued.Id(row.Target) && summary.Name == row.Name &&
                    summary.HostPattern == ProxyPermissionPlan.Host(1) && summary.FolderId == issued.Id(row.Folder) &&
                    summary.IsEnabled == true && !summary.HasCredentials, "effect-mismatch");
            else value = plan.Snapshot(row, issued, summary, row.Action == ProxyPermissionAction.Edit ? 2 : 1);
        }
        return new(row, tokens.Hash, result.Status, receipt?.Evidence, value, true,
            row.Action is ProxyPermissionAction.Create or ProxyPermissionAction.Edit ? request.Target.SecondaryId! : ProxyPermissionContract.RawHash([]));
    }
    internal static async ValueTask InventoryAsync(NativeEnvironment env, ProxyPermissionRoot root, ProxyPermissionPlan plan,
        ProxyPermissionIssued issued, IEnumerable<ProxyPermissionState> expected, CancellationToken token)
    {
        var all = expected.ToArray(); var client = env.CreateManagementClient();
        foreach (var scope in plan.Rows.Select(r => (Project: issued.Id(r.Project), r.Environment, r.SecretPath)).Where(s => s.Project.Length > 0).Distinct())
        {
            var authority = new ManagementAuthority(client.Authority, env.Tokens(NativeIdentityRole.Observer), root.Organization, scope.Project);
            using var list = ProxiedServiceAdministrationOperations.List(root.Organization, scope.Project, scope.Environment, scope.SecretPath);
            var result = await client.ExecuteAsync(list, authority, authority.IssueGrant(list.OperationId, list.Target), cancellationToken: token);
            ProxyPermissionContract.Require(result.IsSuccess, "effect-mismatch"); using var inventory = result.Value;
            var selected = all.Where(s => s.Project == scope.Project && s.Environment == scope.Environment && s.SecretPath == scope.SecretPath).ToArray();
            ProxyPermissionContract.Require(inventory.Services.Select(s => s.Id).Order().SequenceEqual(selected.Select(s => s.Target).Order()), "effect-mismatch");
            foreach (var state in selected)
            {
                var row = plan.Rows.Single(r => r.Key == state.Row);
                ProxyPermissionContract.Require(plan.Snapshot(row, issued, inventory.Services.Single(s => s.Id == state.Target), state.Version) == state, "effect-mismatch");
                using var get = ProxiedServiceAdministrationOperations.Get(root.Organization, state.Project, state.Target);
                var fetched = await client.ExecuteAsync(get, authority, authority.IssueGrant(get.OperationId, get.Target), cancellationToken: token);
                ProxyPermissionContract.Require(fetched.IsSuccess, "effect-mismatch"); using var readback = fetched.Value;
                ProxyPermissionContract.Require(plan.Snapshot(row, issued, readback, state.Version) == state, "effect-mismatch");
                using var named = ProxiedServiceAdministrationOperations.GetByName(root.Organization, state.Project, state.Environment, state.Name, state.SecretPath);
                var found = await client.ExecuteAsync(named, authority, authority.IssueGrant(named.OperationId, named.Target), cancellationToken: token);
                ProxyPermissionContract.Require(found.IsSuccess, "effect-mismatch"); using var byName = found.Value;
                ProxyPermissionContract.Require(plan.Snapshot(row, issued, byName, state.Version) == state, "effect-mismatch");
            }
        }
        // The SDK exposes no deleted-credential inventory. Complete retirement is
        // supplied by independent signed journals, never inferred from list absence.
        foreach (var row in plan.Rows.Where(r => issued.Id(r.Target).Length > 0 && !all.Any(s => s.Row == r.Key)))
        {
            var authority = new ManagementAuthority(client.Authority, env.Tokens(NativeIdentityRole.Observer), root.Organization, issued.Id(row.Project));
            using var get = ProxiedServiceAdministrationOperations.Get(root.Organization, issued.Id(row.Project), issued.Id(row.Target));
            var result = await client.ExecuteAsync(get, authority, authority.IssueGrant(get.OperationId, get.Target), cancellationToken: token);
            if (result.IsSuccess) result.Value.Dispose();
            ProxyPermissionContract.Require(result.Status == SecretStatus.Absent, "effect-mismatch");
        }
    }
}
