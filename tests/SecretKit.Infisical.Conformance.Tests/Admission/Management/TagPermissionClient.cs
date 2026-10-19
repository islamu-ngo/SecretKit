using SecretKit.Core;
using SecretKit.TestFixtures;

namespace SecretKit.Infisical.Conformance.Tests;

// Coordinates are setup-owned typed facts, not a runtime read grant. Each fresh
// private client dispatches exactly one selected principal, with no bootstrap,
// retry, source transition or fallback. Provider ingress corroborates its token.
internal sealed class TagPermissionTokens(IInfisicalTokenSource source) : IInfisicalTokenSource
{
    private int used;
    internal string Hash { get; private set; } = "";
    public async ValueTask<SecretOutcome<InfisicalAccessToken>> GetTokenAsync(CancellationToken token)
    {
        token.ThrowIfCancellationRequested();
        TagPermissionContract.Require(Interlocked.Exchange(ref used, 1) == 0);
        var result = await source.GetTokenAsync(token);
        if (result.IsSuccess)
        {
            try { token.ThrowIfCancellationRequested(); Hash = TagPermissionContract.Hash(result.Value.Material.Reveal()); }
            catch { result.Value.Dispose(); throw; }
        }
        return result;
    }
}
internal static class TagPermissionClient
{
    internal static TagPermissionValue Value(InfisicalTag tag) =>
        new(Guid.Parse(tag.Id), tag.ProjectId, tag.Name ?? "", tag.Slug, tag.Color ?? "");
    internal static async ValueTask<TagPermissionAttempt> ExecuteAsync(NativeEnvironment env,
        TagPermissionRoot root, TagPermissionTrial trial, TagPermissionRow row, bool after,
        CancellationToken token)
    {
        NativeIdentityRole role = row.Principal == root.Authorities.Runtime ? NativeIdentityRole.Runtime :
            row.Principal == root.Authorities.Setup ? NativeIdentityRole.Setup :
            row.Principal == root.Authorities.Administrative ? NativeIdentityRole.Administrative :
            row.Principal == root.Authorities.Denied ? NativeIdentityRole.Denied :
            row.Principal == root.Authorities.Observer ? NativeIdentityRole.Observer :
            throw new NativeCaseFailureException("missing-input");
        var tokens = new TagPermissionTokens(env.Tokens(role));
        await using var client = new InfisicalClient(env.Origin, tokens,
            network: new() { AllowLoopbackDevelopmentHttp = env.AllowLoopbackDevelopmentHttp });
        var address = new InfisicalTagAddress(row.Project, row.List ? null :
            row.Action == TagPermissionAction.Create ? row.TagSlug : row.Id.ToString(),
            row.Action == TagPermissionAction.Create ? InfisicalOrganizationSelector.Slug : InfisicalOrganizationSelector.Id);
        var target = new SecretReference(client.Authority, address);
        // Native mutations select authority tokens, reads select client tokens.
        var mutationTokens = new TagPermissionTokens(env.Tokens(role));
        var authority = new InfisicalNativeAuthority(client.Authority, mutationTokens, row.Project);
        MutationReceipt? receipt = row.Action == TagPermissionAction.Read ? null : new(target);
        SecretStatus status; TagPermissionValue[] values = []; bool complete = true;
        if (row.List)
        {
            var result = await client.ListTagsAsync(target, maximumItems: 1000, cancellationToken: token);
            status = result.Status;
            if (result.IsSuccess) { values = result.Value.Items.Select(Value).ToArray(); complete = result.Value.IsComplete; }
        }
        else
        {
            var result = row.Action switch
            {
                TagPermissionAction.Read => await client.GetTagAsync(target, token),
                TagPermissionAction.Create => await client.CreateTagAsync(target, "#A1B2C3", authority, receipt!, token),
                TagPermissionAction.Edit => await client.UpdateTagAsync(target, row.TagSlug + "-changed", "#A1B2C3", authority, receipt!, token),
                TagPermissionAction.Delete => await client.DeleteTagAsync(target, authority, receipt!, cancellationToken: token),
                _ => throw new NativeCaseFailureException("contract-mismatch")
            };
            status = result.Status;
            if (result.IsSuccess) values = [Value(result.Value)];
        }
        return new(row, row.Action == TagPermissionAction.Read ? tokens.Hash : mutationTokens.Hash, null,
            status, receipt?.Evidence, values, complete);
    }
}
