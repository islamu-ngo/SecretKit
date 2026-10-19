using System.Security.Cryptography;
using SecretKit.Core;
using SecretKit.Infisical.Management;
using SecretKit.TestFixtures;

namespace SecretKit.Infisical.Conformance.Tests;

internal static class IdentityPermissionClient
{
    internal static MemberPermissionTokens Tokens(NativeEnvironment env, IdentityPermissionRoot root, IdentityPermissionActor actor) =>
        actor.Owned ? new(actor.Credential) : new(env.Tokens(actor.Principal == root.Authorities.Runtime ? NativeIdentityRole.Runtime :
            actor.Principal == root.Authorities.Denied ? NativeIdentityRole.Denied : throw new NativeCaseFailureException("missing-input")));
    internal static string Method(IdentityPermissionAction action) => action switch
    {
        IdentityPermissionAction.Read or IdentityPermissionAction.GetToken => "GET",
        IdentityPermissionAction.Create or IdentityPermissionAction.CreateToken or IdentityPermissionAction.DeleteToken or IdentityPermissionAction.AssignAdditionalPrivileges => "POST",
        IdentityPermissionAction.Delete or IdentityPermissionAction.RevokeAuth => "DELETE",
        _ => "PATCH"
    };
    internal static string Path(IdentityPermissionRoot root, IdentityPermissionPlan plan, IdentityPermissionIssued issued, IdentityPermissionRow row)
    {
        if (IdentityPermissionContract.TokenAction(row.Action)) return row.Action == IdentityPermissionAction.DeleteToken ?
            "/api/v1/auth/token-auth/tokens/" + issued.Id(row.Token) + "/revoke" :
            "/api/v1/auth/token-auth/identities/" + issued.Id(row.Identity) + (row.Action is IdentityPermissionAction.CreateToken or IdentityPermissionAction.GetToken ? "/tokens" : "");
        if (row.Action == IdentityPermissionAction.AssignAdditionalPrivileges) return "/api/v2/identity-project-additional-privilege";
        if (root.ScopeProfile == IdentityPermissionScope.Organization) return "/api/v1/identities" +
            (row.Action == IdentityPermissionAction.Create ? "" : "/" + issued.Id(row.Identity));
        return "/api/v1/projects/" + issued.Id(row.Project) + (row.Action == IdentityPermissionAction.Edit ? "/identities/" : "/memberships/identities/") + issued.Id(row.Identity);
    }
    internal static async ValueTask<IdentityPermissionAttempt> ExecuteAsync(NativeEnvironment env, IdentityPermissionRoot root,
        IdentityPermissionPlan plan, IdentityPermissionIssued issued, IdentityPermissionRow row,
        Func<string, SecretMaterial, ValueTask> capture, CancellationToken token)
    {
        using var tokens = Tokens(env, root, issued.Actors[row.Actor]); var client = env.CreateManagementClient();
        string org = issued.Id(row.Organization), project = issued.Id(row.Project), identity = issued.Id(row.Identity), membership = issued.Id(row.Membership);
        string role = row.Control == "role" ? "admin" : plan.Role;
        bool scoped = root.ScopeProfile == IdentityPermissionScope.Project;
        if (IdentityPermissionContract.TokenAction(row.Action))
        {
            var held = issued.Targets.SingleOrDefault(t => t.Row == row.Key);
            if (held is not null) await ProbeAsync(env, org, project, issued.Id(row.Canary), held.Material, token);
            IdentityPermissionAttempt attempt;
            if (row.Action == IdentityPermissionAction.CreateToken)
            {
                using var request = IdentityAuthenticationOperations.CreateToken(org, identity, row.Name);
                var result = await Send(request);
                if (result.Outcome.IsSuccess)
                {
                    using var creation = result.Outcome.Value;
                    await capture(creation.Metadata.Id, creation.AccessToken);
                    char[] characters = creation.AccessToken.ExportCharacters();
                    byte[] material;
                    try { material = System.Text.Encoding.UTF8.GetBytes(characters); } finally { Array.Clear(characters); }
                    try { await ProbeAsync(env, org, project, issued.Id(row.Canary), material, token); }
                    finally { CryptographicOperations.ZeroMemory(material); }
                    return Result(result.Outcome.Status, result.Receipt, request, identity, value: creation.Metadata.Id);
                }
                return Result(result.Outcome.Status, result.Receipt, request, "");
            }
            if (row.Action == IdentityPermissionAction.GetToken)
            {
                using var request = IdentityAuthenticationOperations.ListTokens(org, identity); var result = await Send(request);
                attempt = Result(result.Outcome.Status, result.Receipt, request, identity,
                    value: result.Outcome.IsSuccess && result.Outcome.Value.Items.Count == 1 ? result.Outcome.Value.Items[0].Id : "",
                    complete: !result.Outcome.IsSuccess || result.Outcome.Value.IsComplete);
            }
            else if (row.Action == IdentityPermissionAction.DeleteToken)
            {
                using var request = IdentityAuthenticationOperations.RevokeToken(org, issued.Id(row.Token)); var result = await Send(request);
                attempt = Result(result.Outcome.Status, result.Receipt, request, identity);
            }
            else
            {
                using var request = row.Action == IdentityPermissionAction.EditAuth ?
                    IdentityAuthenticationOperations.UpdateTokenAuth(org, identity, new(accessTokenTTL: 900)) :
                    IdentityAuthenticationOperations.DeleteTokenAuth(org, identity);
                var result = await Send(request); attempt = Result(result.Outcome.Status, result.Receipt, request, identity);
            }
            IdentityPermissionContract.Require(held is not null);
            await ProbeAsync(env, org, project, issued.Id(row.Canary), held!.Material, token);
            return attempt;
        }
        if (row.Action == IdentityPermissionAction.AssignAdditionalPrivileges)
        {
            var selection = new LegacyPrivilegeSelection(org, project, plan.ProjectSlug, identity, membership);
            var change = new ProjectPrivilegeChange([new(row.Control == "subject" ? ProjectRoleSubject.Groups : ProjectRoleSubject.Identity,
                row.Control == "action" ? ProjectRoleAction.Delete : ProjectRoleAction.Read)], PrivilegeLifetime.Permanent(), row.Name);
            using var request = IdentityPrivilegeChangeOperations.CreateProjectPrivilege(selection, change); var result = await Send(request);
            return Result(result.Outcome.Status, result.Receipt, request, identity, value: result.Outcome.IsSuccess ? result.Outcome.Value.Id : "");
        }
        if (scoped && row.Action == IdentityPermissionAction.Read)
        {
            using var request = MembershipOperations.GetProjectIdentityMembership(org, project, identity); var result = await Send(request);
            return Result(result.Outcome.Status, result.Receipt, request, result.Outcome.IsSuccess ? result.Outcome.Value.IdentityId : "",
                result.Outcome.IsSuccess ? result.Outcome.Value.Id : "", result.Outcome.IsSuccess ? result.Outcome.Value.Identity.Name : "");
        }
        if (scoped && row.Action != IdentityPermissionAction.Edit)
        {
            using var request = row.Action switch
            {
                IdentityPermissionAction.Create => MembershipOperations.AddProjectIdentity(org, project, identity, new MembershipRoleSelection(role: "no-access")),
                IdentityPermissionAction.AssignRole => MembershipOperations.UpdateProjectIdentityRoles(org, project, identity, [new(role)]),
                IdentityPermissionAction.Delete => MembershipOperations.RemoveProjectIdentity(org, project, identity),
                _ => throw new NativeCaseFailureException("observer-unavailable")
            };
            var result = await Send(request);
            return Result(result.Outcome.Status, result.Receipt, request, result.Outcome.IsSuccess ? result.Outcome.Value.PrincipalId : "",
                result.Outcome.IsSuccess ? result.Outcome.Value.Id : "");
        }
        using var native = scoped ? IdentityOperations.UpdateProjectIdentity(org, project, identity, name: row.Name + "-edited") : row.Action switch
        {
            IdentityPermissionAction.Read => IdentityOperations.GetOrganizationIdentity(org, identity),
            IdentityPermissionAction.Create => IdentityOperations.CreateOrganizationIdentity(org, row.Name, "no-access"),
            IdentityPermissionAction.Edit => IdentityOperations.UpdateOrganizationIdentity(org, identity, name: row.Name + "-edited"),
            IdentityPermissionAction.GrantPrivileges => IdentityOperations.UpdateOrganizationIdentity(org, identity, role: role),
            IdentityPermissionAction.Delete => IdentityOperations.DeleteOrganizationIdentity(org, identity),
            _ => throw new NativeCaseFailureException("observer-unavailable")
        };
        var response = await Send(native);
        return Result(response.Outcome.Status, response.Receipt, native, response.Outcome.IsSuccess ? response.Outcome.Value.Id : "",
            name: response.Outcome.IsSuccess ? response.Outcome.Value.Name : "");
        IdentityPermissionAttempt Result<T>(SecretStatus status, ManagementReceipt? receipt, ManagementRequest<T> request, string id,
            string member = "", string name = "", string value = "", bool complete = true) where T : notnull =>
            new(row, tokens.Hash, status, receipt?.Evidence, id, member, name, value, complete, request.Target.SecondaryId ?? "");
        async ValueTask<(SecretOutcome<T> Outcome, ManagementReceipt? Receipt)> Send<T>(ManagementRequest<T> request) where T : notnull
        {
            var authority = new ManagementAuthority(client.Authority, tokens, org, request.Target.ProjectId);
            var receipt = request.IsMutation ? client.CreateReceipt(request) : null;
            return (await client.ExecuteAsync(request, authority, authority.IssueGrant(request.OperationId, request.Target), receipt, token), receipt);
        }
    }
    // A source-owned read policy is assigned only to TARGET, never to ACTOR.
    // This typed request authenticates a token; it does not prove policy effect.
    internal static async ValueTask ProbeAsync(NativeEnvironment env, string org, string project, string canary, byte[] material, CancellationToken token)
    {
        using var tokens = new MemberPermissionTokens(material); var client = env.CreateManagementClient();
        using var request = project.Length == 0 ? IdentityOperations.GetOrganizationIdentity(org, canary) : IdentityOperations.GetProjectIdentity(org, project, canary);
        var authority = new ManagementAuthority(client.Authority, tokens, org, request.Target.ProjectId);
        var result = await client.ExecuteAsync(request, authority, authority.IssueGrant(request.OperationId, request.Target), cancellationToken: token);
        IdentityPermissionContract.Require(result.Status is SecretStatus.Success or SecretStatus.Denied);
        if (result.IsSuccess) IdentityPermissionContract.Require(result.Value.Id == canary);
        // 401 and 403 can share the SDK's bounded status. Only the independent
        // authentication journal distinguishes them; never infer validity here.
    }
}
