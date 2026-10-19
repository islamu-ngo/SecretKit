using SecretKit.Infisical.Management;
using SecretKit.TestFixtures;

namespace SecretKit.Infisical.Conformance.Tests;

internal static class LegacyIdentityPrivilegesEffects
{
    internal static async ValueTask ExecuteAsync(ProjectFamilyContext c, CancellationToken token)
    {
        var scenario = await PermissionPrivilegeScenario.CreateAsync(c, true, true, false, token);
        if (c.Operation == "ListPrivileges")
            await c.CaseAsync(() => LegacyIdentityPrivilegeOperations.ListPrivileges(scenario.Selection),
                page => page.IsComplete && page.Items.Any(scenario.Match),
                (_, ct) => scenario.ObserveAsync(true, true, ct), token);
        else if (c.Operation == "GetPrivilege")
            await c.CaseAsync(() => LegacyIdentityPrivilegeOperations.GetPrivilege(scenario.Selection, scenario.Slug),
                scenario.Match, (_, ct) => scenario.ObserveAsync(true, true, ct), token);
        else if (c.Operation == "DeletePrivilege")
            await c.CaseAsync(() => LegacyIdentityPrivilegeOperations.DeletePrivilege(scenario.Selection, scenario.Slug),
                scenario.Match, (applied, ct) => scenario.ObserveAsync(!applied, true, ct), token);
        else throw new NativeCaseFailureException("contract-mismatch");
    }
}
