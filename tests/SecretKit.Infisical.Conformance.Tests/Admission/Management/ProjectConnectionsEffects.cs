using SecretKit.Infisical.Management;
using SecretKit.TestFixtures;

namespace SecretKit.Infisical.Conformance.Tests;

internal static class ProjectConnectionsEffects
{
    internal static async ValueTask ExecuteAsync(ProjectFamilyContext c, CancellationToken token)
    {
        // An owned empty project is an independently prepared bounded collection.
        // This does not provision or resurrect the removed connector catalog.
        await c.EnsureProjectAsync(token);
        if (c.Operation == "ListAuthorizations")
        {
            Func<ManagementRequest<ManagementPage<ProjectConnectionAuthorization>>> request =
                () => ProjectConnectionOperations.ListAuthorizations(c.OrganizationId, c.ProjectId);
            await c.CaseAsync(request, page => page.IsComplete && page.Items.Count == 0,
                async (_, ct) =>
                {
                    var observed = await c.ExecuteAsync(request, NativeIdentityRole.Observer, ct);
                    return observed.IsSuccess && observed.Value.IsComplete && observed.Value.Items.Count == 0;
                }, token);
        }
        else if (c.Operation == "ListIntegrations")
        {
            Func<ManagementRequest<ManagementPage<ProjectConnectionIntegration>>> request =
                () => ProjectConnectionOperations.ListIntegrations(c.OrganizationId, c.ProjectId);
            await c.CaseAsync(request, page => page.IsComplete && page.Items.Count == 0,
                async (_, ct) =>
                {
                    var observed = await c.ExecuteAsync(request, NativeIdentityRole.Observer, ct);
                    return observed.IsSuccess && observed.Value.IsComplete && observed.Value.Items.Count == 0;
                }, token);
        }
        else c.Probe.Contract(false, NativeFailure.ContractMismatch);
    }
}
