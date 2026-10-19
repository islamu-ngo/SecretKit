using SecretKit.Core;
using SecretKit.Infisical.Management;
using SecretKit.TestFixtures;

namespace SecretKit.Infisical.Conformance.Tests;

// Separate observer authority. The exercising principal never receives a read grant.
internal static class WorkspacePermissionReadback
{
    internal static async ValueTask CheckAsync(NativeEnvironment env, WorkspacePermissionRoot root,
        WorkspacePermissionTrial trial, CancellationToken token)
    {
        var client = env.CreateManagementClient();
        using var list = ProjectOperations.ListProjects(root.Organization);
        var observer = new ManagementAuthority(client.Authority, env.Tokens(NativeIdentityRole.Observer), root.Organization);
        var inventory = await client.ExecuteAsync(list, observer, observer.IssueGrant(list.OperationId, list.Target), cancellationToken: token);
        var expected = trial.Inventory;
        WorkspacePermissionContract.Require(inventory.IsSuccess && inventory.Value.IsComplete &&
            inventory.Value.Items.Select(p => p.Id).Order().SequenceEqual(expected.Select(p => p.Target).Order()), "effect-mismatch");
        foreach (var binding in trial.Issued.Bindings.Where(b => b.Kind == "project"))
        {
            using var get = ProjectOperations.GetProject(root.Organization, binding.CanonicalId);
            var authority = new ManagementAuthority(client.Authority, env.Tokens(NativeIdentityRole.Observer), root.Organization, binding.CanonicalId);
            var result = await client.ExecuteAsync(get, authority, authority.IssueGrant(get.OperationId, get.Target), cancellationToken: token);
            var state = expected.SingleOrDefault(s => s.Target == binding.CanonicalId);
            WorkspacePermissionContract.Require(result.Status == (state is null ? SecretStatus.Absent : SecretStatus.Success), "effect-mismatch");
            if (state is null) continue;
            var value = result.Value;
            WorkspacePermissionContract.Require(value.Environments.IsPresent && value.Environments.Value.Count == 0 &&
                value.DeletedEnvironments.IsPresent && value.DeletedEnvironments.Value.Count == 0, "effect-mismatch");
            var row = new WorkspacePermissionRow("", "", "", WorkspacePermissionAction.Edit, "@" + state.Organization,
                state.Project.Length == 0 ? "" : "@" + state.Project, state.Row, state.Name, state.Slug, 0);
            WorkspacePermissionContract.Require(trial.Plan.Snapshot(row, trial.Issued, value, state.Version) == state, "effect-mismatch");
            using var bySlug = ProjectOperations.GetProjectBySlug(root.Organization, state.Slug);
            var fetched = await client.ExecuteAsync(bySlug, observer, observer.IssueGrant(bySlug.OperationId, bySlug.Target), cancellationToken: token);
            WorkspacePermissionContract.Require(fetched.IsSuccess && fetched.Value.Id == state.Target &&
                trial.Plan.Snapshot(row, trial.Issued, fetched.Value, state.Version) == state, "effect-mismatch");
        }
    }
}
