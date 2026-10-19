using System.Globalization;
using SecretKit.Core;
using SecretKit.Infisical.Management;
using SecretKit.TestFixtures;

namespace SecretKit.Infisical.Conformance.Tests;

internal static class AuditPermissionClient
{
    internal const int PageSize = 2, MaximumPages = 16;
    internal static string SeedPath(AuditPermissionRoot root, AuditPermissionIssued issued, AuditPermissionSeed seed) =>
        root.ScopeProfile == AuditPermissionScope.Organization ? "/api/v1/organization/roles" : "/api/v1/projects/" + issued.Id(seed.Project) + "/roles";
    internal static ManagementRequest<RoleSummary> SeedRequest(AuditPermissionRoot root, AuditPermissionIssued issued, AuditPermissionSeed seed) =>
        root.ScopeProfile == AuditPermissionScope.Organization ? RoleChangeOperations.CreateOrganizationRole(issued.Id(seed.Organization),
            new(seed.Name, seed.Slug, new("closed-seed"), [])) : RoleChangeOperations.CreateProjectRole(issued.Id(seed.Organization), issued.Id(seed.Project),
            new(seed.Name, seed.Slug, new("closed-seed"), []));
    internal static async ValueTask<AuditPermissionSeedReceipt> SeedAsync(NativeEnvironment env, AuditPermissionRoot root,
        AuditPermissionIssued issued, AuditPermissionSeed seed, CancellationToken token)
    {
        using var request = SeedRequest(root, issued, seed); var client = env.CreateManagementClient();
        var receipt = client.CreateReceipt(request);
        var authority = env.CreateManagementAuthority(client, NativeIdentityRole.Setup, issued.Id(seed.Organization), request.Target.ProjectId);
        var result = await client.ExecuteAsync(request, authority, authority.IssueGrant(request.OperationId, request.Target), receipt, token);
        AuditPermissionContract.Require(result.IsSuccess && receipt.Evidence == DispatchEvidence.Applied &&
            result.Value.Name == seed.Name && result.Value.Slug == seed.Slug && result.Value.Description == "closed-seed" &&
            result.Value.IncludesPermissions && result.Value.Permissions is { Count: 0 }, "effect-mismatch");
        return new(seed, new(receipt, result.Status, false, request.Target.SecondaryId!), result.Value.Id);
    }
    internal static AuditSelectors Selectors(AuditPermissionRoot root, AuditPermissionPlan plan) => new(actor: root.Authorities.Setup,
        actorType: "identity", eventClass: AuditEventFilter.Classes([AuditEventClass.Management]), eventType: AuditEventFilter.Types([plan.EventType]));
    internal static ManagementRequest<ManagementPage<AuditRow>> Request(AuditPermissionRoot root, AuditPermissionPlan plan,
        AuditPermissionIssued issued, AuditPermissionRow row, int offset) => GovernanceOperations.ReadAudit(issued.Id(row.Organization),
            root.From, root.Until, row.Project.Length == 0 ? null : issued.Id(row.Project), offset, PageSize, Selectors(root, plan));
    internal static AuditPermissionView View(AuditEntry entry) => new(entry.Id, entry.ProjectId ?? "", entry.ActorType, entry.EventType,
        entry.EventClass, DateTimeOffset.Parse(entry.CreatedAt, CultureInfo.InvariantCulture));
    internal static async ValueTask<AuditPermissionAttempt> ExecuteAsync(NativeEnvironment env, AuditPermissionRoot root,
        AuditPermissionPlan plan, AuditPermissionIssued issued, AuditPermissionRow row, CancellationToken token)
    {
        var actor = issued.Actors[row.Actor];
        var client = env.CreateManagementClient(); var pages = new List<AuditPermissionPage>(); int offset = 0;
        for (int i = 0; i < MaximumPages; i++)
        {
            using var tokens = actor.Owned ? new MemberPermissionTokens(actor.Credential) :
                new MemberPermissionTokens(env.Tokens(actor.Principal == root.Authorities.Denied ? NativeIdentityRole.Denied : NativeIdentityRole.Runtime));
            using var request = Request(root, plan, issued, row, offset);
            var authority = new ManagementAuthority(client.Authority, tokens, issued.Id(row.Organization), request.Target.ProjectId);
            var result = await client.ExecuteAsync(request, authority, authority.IssueGrant(request.OperationId, request.Target), cancellationToken: token);
            AuditPermissionContract.Require(tokens.Hash == actor.CredentialHash, "effect-mismatch");
            if (!result.IsSuccess)
            {
                pages.Add(new(offset, PageSize, request.Target.SecondaryId!, result.Status, [], true));
                return new(row, tokens.Hash, pages.ToArray());
            }
            var page = result.Value;
            AuditPermissionContract.Require(page.Items.Select(r => r.Ordinal).SequenceEqual(Enumerable.Range(offset, page.Items.Count)) &&
                page.Items.All(r => r.Outcome.IsSuccess), "effect-mismatch");
            var values = page.Items.Select(r => View(r.Outcome.Value)).ToArray();
            pages.Add(new(offset, PageSize, request.Target.SecondaryId!, result.Status, values, page.IsComplete));
            if (page.IsComplete)
            {
                AuditPermissionContract.Require(page.NextOffset is null && values.Length < PageSize, "effect-mismatch");
                return new(row, tokens.Hash, pages.ToArray());
            }
            AuditPermissionContract.Require(values.Length == PageSize && page.NextOffset == offset + PageSize, "effect-mismatch");
            offset += PageSize;
        }
        throw new SecretKit.TestFixtures.NativeCaseFailureException("effect-mismatch");
    }
}
