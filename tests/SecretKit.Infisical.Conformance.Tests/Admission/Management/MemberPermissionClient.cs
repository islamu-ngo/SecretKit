using System.Text;
using SecretKit.Core;
using SecretKit.Infisical.Management;
using SecretKit.TestFixtures;

namespace SecretKit.Infisical.Conformance.Tests;

internal sealed class MemberPermissionTokens : IInfisicalTokenSource, IDisposable
{
    private readonly IInfisicalTokenSource? borrowed;
    private readonly SecretMaterial? owned;
    private int used;
    internal string Hash { get; private set; } = "";
    internal MemberPermissionTokens(IInfisicalTokenSource borrowed) => this.borrowed = borrowed;
    internal MemberPermissionTokens(byte[] bytes)
    {
        char[] chars = Encoding.UTF8.GetChars(bytes);
        try { owned = SecretMaterial.FromText(chars); } finally { Array.Clear(chars); }
    }
    public async ValueTask<SecretOutcome<InfisicalAccessToken>> GetTokenAsync(CancellationToken token)
    {
        token.ThrowIfCancellationRequested();
        MemberPermissionContract.Require(Interlocked.Exchange(ref used, 1) == 0);
        var result = owned is null ? await borrowed!.GetTokenAsync(token) :
            SecretOutcome<InfisicalAccessToken>.Success(new(owned.Copy()));
        if (result.IsSuccess)
        {
            try
            {
                token.ThrowIfCancellationRequested();
                char[] chars = result.Value.Material.ExportCharacters();
                byte[] bytes = Encoding.UTF8.GetBytes(chars);
                try { Hash = MemberPermissionContract.RawHash(bytes); }
                finally { Array.Clear(chars); System.Security.Cryptography.CryptographicOperations.ZeroMemory(bytes); }
            }
            catch { result.Value.Dispose(); throw; }
        }
        return result;
    }
    public void Dispose() => owned?.Dispose();
}
internal static class MemberPermissionClient
{
    internal static MemberPermissionTokens Tokens(NativeEnvironment env, MemberPermissionRoot root, MemberPermissionPrincipal actor) =>
        actor.Owned ? new(actor.Credential) : new(env.Tokens(actor.Id == root.Authorities.Runtime ? NativeIdentityRole.Runtime :
            actor.Id == root.Authorities.Denied ? NativeIdentityRole.Denied : throw new NativeCaseFailureException("missing-input")));
    internal static string Method(MemberPermissionScope scope, MemberPermissionAction action) => action switch
    {
        MemberPermissionAction.Read => scope == MemberPermissionScope.Project ? "POST" : "GET",
        MemberPermissionAction.Create => "POST",
        MemberPermissionAction.Delete => "DELETE",
        MemberPermissionAction.Edit or MemberPermissionAction.AssignRole or MemberPermissionAction.GrantPrivileges => "PATCH",
        _ => throw new NativeCaseFailureException("observer-unavailable")
    };
    internal static string Path(MemberPermissionScope scope, MemberPermissionRow row) =>
        scope == MemberPermissionScope.Organization ?
            "/api/v2/organizations/" + row.Organization + "/memberships" + (row.Action == MemberPermissionAction.Read ? "" : "/" + row.Membership) :
            "/api/v1/projects/" + row.Project + "/memberships" + (row.Action == MemberPermissionAction.Read ? "/details" :
                row.Action == MemberPermissionAction.AssignRole ? "/" + row.Membership : "");
    internal static async ValueTask<MemberPermissionAttempt> ExecuteAsync(NativeEnvironment env,
        MemberPermissionRoot root, MemberPermissionIssued issued, MemberPermissionRow row, CancellationToken token)
    {
        using var tokens = Tokens(env, root, issued.Principals[row.Actor]);
        var client = env.CreateManagementClient();
        if (root.ScopeProfile == MemberPermissionScope.Organization)
        {
            if (row.Action == MemberPermissionAction.Read)
            {
                using var request = OrganizationMembershipOperations.ListOrganizationMemberships(row.Organization);
                var result = await Send(request);
                return new(row, tokens.Hash, result.Outcome.Status, null,
                    result.Outcome.IsSuccess ? result.Outcome.Value.Items.Select(v => new MemberPermissionState(v.Id,
                        v.UserId ?? v.User!.Id, row.Organization, "", v.User!.Username, v.Role, v.IsActive ?? false, 0)).ToArray() : [],
                    !result.Outcome.IsSuccess || result.Outcome.Value.IsComplete);
            }
            using var mutation = row.Action switch
            {
                MemberPermissionAction.Edit => OrganizationMembershipOperations.UpdateOrganizationMembership(
                    row.Organization, row.Membership, isActive: false),
                MemberPermissionAction.GrantPrivileges => OrganizationMembershipOperations.UpdateOrganizationMembership(
                    row.Organization, row.Membership, role: issued.AssignedRole),
                MemberPermissionAction.Delete => OrganizationMembershipOperations.DeleteOrganizationMembership(row.Organization, row.Membership),
                _ => throw new NativeCaseFailureException("observer-unavailable")
            };
            var changed = await Send(mutation);
            return new(row, tokens.Hash, changed.Outcome.Status, changed.Receipt?.Evidence,
                changed.Outcome.IsSuccess ? [new(changed.Outcome.Value.Id, changed.Outcome.Value.UserId ?? "",
                    changed.Outcome.Value.OrganizationId, "", "", changed.Outcome.Value.Role, changed.Outcome.Value.IsActive ?? false, 0)] : [], true);
        }
        if (row.Action == MemberPermissionAction.Read)
        {
            using var request = ProjectMembershipOperations.InspectProjectMembershipByUsername(row.Organization, row.Project, row.User.Username);
            var result = await Send(request);
            return new(row, tokens.Hash, result.Outcome.Status, null, result.Outcome.IsSuccess ?
                [new(result.Outcome.Value.Id, result.Outcome.Value.UserId, row.Organization, row.Project,
                    result.Outcome.Value.User.Username, result.Outcome.Value.Roles.Single().Role, true, 0)] : [], true);
        }
        if (row.Action == MemberPermissionAction.AssignRole)
        {
            using var request = ProjectMembershipOperations.UpdateProjectMembershipRoles(row.Organization, row.Project,
                row.Membership, [new(issued.AssignedRole)]);
            var result = await Send(request);
            MemberPermissionContract.Require(!result.Outcome.IsSuccess || result.Outcome.Value.IsComplete &&
                result.Outcome.Value.Items.Count == 1 && result.Outcome.Value.Items[0].Role == issued.AssignedRole, "effect-mismatch");
            // This response attests roles, not user identity: independent membership/storage journals bind the user.
            return new(row, tokens.Hash, result.Outcome.Status, result.Receipt?.Evidence, result.Outcome.IsSuccess ?
                [new(row.Membership, row.User.Id, row.Organization, row.Project, "", issued.AssignedRole, true, 0)] : [], true);
        }
        using var batch = row.Action switch
        {
            MemberPermissionAction.Create => MembershipMutationOperations.InviteProjectMembers(row.Organization, row.Project,
                new(usernames: [row.User.Username]), ["no-access"]),
            MemberPermissionAction.Delete => MembershipMutationOperations.RemoveProjectMembers(row.Organization, row.Project,
                new(usernames: [row.User.Username])),
            _ => throw new NativeCaseFailureException("observer-unavailable")
        };
        var members = await Send(batch);
        return new(row, tokens.Hash, members.Outcome.Status, members.Receipt?.Evidence, members.Outcome.IsSuccess ?
            members.Outcome.Value.Items.Select(v => new MemberPermissionState(v.Id, v.UserId, row.Organization, v.ProjectId,
                "", "", true, 0)).ToArray() : [], !members.Outcome.IsSuccess || members.Outcome.Value.IsComplete);

        async ValueTask<(SecretOutcome<T> Outcome, ManagementReceipt? Receipt)> Send<T>(ManagementRequest<T> request) where T : notnull
        {
            var authority = new ManagementAuthority(client.Authority, tokens, row.Organization,
                root.ScopeProfile == MemberPermissionScope.Project ? row.Project : null);
            var receipt = request.IsMutation ? client.CreateReceipt(request) : null;
            return (await client.ExecuteAsync(request, authority, authority.IssueGrant(request.OperationId, request.Target),
                receipt, token), receipt);
        }
    }
}
