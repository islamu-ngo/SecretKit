using SecretKit.Core;
using SecretKit.TestFixtures;

namespace SecretKit.Infisical.Conformance.Tests;

// Coordinates are setup-owned typed facts, not a runtime read grant. Each fresh
// private client dispatches exactly one selected principal, with no bootstrap,
// retry, source transition or fallback. Provider ingress corroborates its token.
internal sealed class FolderPermissionTokens(IInfisicalTokenSource source) : IInfisicalTokenSource
{
    private int used;
    internal string Hash { get; private set; } = "";
    public async ValueTask<SecretOutcome<InfisicalAccessToken>> GetTokenAsync(CancellationToken token)
    {
        token.ThrowIfCancellationRequested();
        FolderPermissionContract.Require(Interlocked.Exchange(ref used, 1) == 0);
        var result = await source.GetTokenAsync(token);
        if (result.IsSuccess)
        {
            try { token.ThrowIfCancellationRequested(); Hash = FolderPermissionContract.Hash(result.Value.Material.Reveal()); }
            catch { result.Value.Dispose(); throw; }
        }
        return result;
    }
}
internal static class FolderPermissionClient
{
    internal static FolderPermissionValue Value(InfisicalFolder folder) =>
        new(Guid.Parse(folder.Id), Guid.Parse(folder.EnvironmentId), folder.Name, folder.Description, folder.Path!);
    internal static async ValueTask<FolderPermissionAttempt> ExecuteAsync(NativeEnvironment env,
        FolderPermissionRoot root, FolderPermissionTrial trial, FolderPermissionRow row, bool after,
        CancellationToken token)
    {
        NativeIdentityRole role = row.Principal == root.Authorities.Runtime ? NativeIdentityRole.Runtime :
            row.Principal == root.Authorities.Setup ? NativeIdentityRole.Setup :
            row.Principal == root.Authorities.Administrative ? NativeIdentityRole.Administrative :
            row.Principal == root.Authorities.Denied ? NativeIdentityRole.Denied :
            row.Principal == root.Authorities.Observer ? NativeIdentityRole.Observer :
            throw new NativeCaseFailureException("missing-input");
        var tokens = new FolderPermissionTokens(env.Tokens(role));
        await using var client = new InfisicalClient(env.Origin, tokens,
            network: new() { AllowLoopbackDevelopmentHttp = env.AllowLoopbackDevelopmentHttp });
        var address = new InfisicalFolderAddress(row.Project, row.Environment, row.EnvironmentId.ToString(),
            row.Path, row.Action == FolderPermissionAction.Create || row.List ? null : row.Id.ToString(),
            row.List ? null : row.Name);
        var target = new SecretReference(client.Authority, address);
        // Native mutations select authority tokens, reads select client tokens.
        var mutationTokens = new FolderPermissionTokens(env.Tokens(role));
        var authority = new InfisicalNativeAuthority(client.Authority, mutationTokens, row.Project, row.Environment, row.Path);
        MutationReceipt? receipt = row.Action == FolderPermissionAction.Read ? null : new(target);
        SecretStatus status; FolderPermissionValue[] values = []; bool complete = true;
        if (row.List)
        {
            var result = await client.ListFoldersAsync(target, maximumItems: 1000, cancellationToken: token);
            status = result.Status;
            if (result.IsSuccess) { values = result.Value.Items.Select(Value).ToArray(); complete = result.Value.IsComplete; }
        }
        else
        {
            var result = row.Action switch
            {
                FolderPermissionAction.Read => await client.GetFolderAsync(target, token),
                FolderPermissionAction.Create => await client.CreateFolderAsync(target, authority, receipt!, "changed", token),
                FolderPermissionAction.Edit => await client.UpdateFolderAsync(target, authority, receipt!, "changed", cancellationToken: token),
                FolderPermissionAction.Delete => await client.DeleteFolderAsync(target, authority, receipt!, cancellationToken: token),
                _ => throw new NativeCaseFailureException("contract-mismatch")
            };
            status = result.Status;
            if (result.IsSuccess) values = [Value(result.Value)];
        }
        return new(row, row.Action == FolderPermissionAction.Read ? tokens.Hash : mutationTokens.Hash, null,
            status, receipt?.Evidence, values, complete);
    }
}
