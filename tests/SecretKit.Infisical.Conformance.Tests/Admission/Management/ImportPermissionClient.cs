using SecretKit.Core;
using SecretKit.TestFixtures;

namespace SecretKit.Infisical.Conformance.Tests;

// Coordinates are setup-owned typed facts, not a runtime read grant. Each fresh
// private client dispatches exactly one selected principal, with no bootstrap,
// retry, source transition or fallback. Provider ingress corroborates its token.
internal sealed class ImportPermissionTokens(IInfisicalTokenSource source) : IInfisicalTokenSource
{
    private int used;
    internal string Hash { get; private set; } = "";
    public async ValueTask<SecretOutcome<InfisicalAccessToken>> GetTokenAsync(CancellationToken token)
    {
        token.ThrowIfCancellationRequested();
        ImportPermissionContract.Require(Interlocked.Exchange(ref used, 1) == 0);
        var result = await source.GetTokenAsync(token);
        if (result.IsSuccess)
        {
            try { token.ThrowIfCancellationRequested(); Hash = ImportPermissionContract.Hash(result.Value.Material.Reveal()); }
            catch { result.Value.Dispose(); throw; }
        }
        return result;
    }
}
internal static class ImportPermissionClient
{
    internal static ImportPermissionValue Value(InfisicalImport value) =>
        new(Guid.Parse(value.Id), Guid.Parse(value.FolderId), value.SourceEnvironment, value.SourcePath,
            value.SourceProjectId!, value.Position, value.IsReplication, value.ReplicationReportedSuccessful,
            value.ReplicationStatus, value.LastReplicated);
    internal static async ValueTask<ImportPermissionAttempt> ExecuteAsync(NativeEnvironment env,
        ImportPermissionRoot root, ImportPermissionTrial trial, ImportPermissionRow row, bool after,
        CancellationToken token)
    {
        NativeIdentityRole role = row.Principal == root.Authorities.Runtime ? NativeIdentityRole.Runtime :
            row.Principal == root.Authorities.Setup ? NativeIdentityRole.Setup :
            row.Principal == root.Authorities.Administrative ? NativeIdentityRole.Administrative :
            row.Principal == root.Authorities.Denied ? NativeIdentityRole.Denied :
            row.Principal == root.Authorities.Observer ? NativeIdentityRole.Observer :
            throw new NativeCaseFailureException("missing-input");
        var tokens = new ImportPermissionTokens(env.Tokens(role));
        await using var client = new InfisicalClient(env.Origin, tokens,
            network: new() { AllowLoopbackDevelopmentHttp = env.AllowLoopbackDevelopmentHttp });
        var address = new InfisicalImportAddress(row.Project, row.Environment, row.Path, row.FolderId.ToString(),
            row.Action == ImportPermissionAction.Create || row.List ? null : row.Id.ToString());
        var target = new SecretReference(client.Authority, address);
        // Native mutations select authority tokens, reads select client tokens.
        var mutationTokens = new ImportPermissionTokens(env.Tokens(role));
        var authority = new InfisicalNativeAuthority(client.Authority, mutationTokens, row.Project, row.Environment, row.Path);
        MutationReceipt? receipt = row.Action == ImportPermissionAction.Read ? null : new(target);
        SecretStatus status; ImportPermissionValue[] values = []; bool complete = true;
        if (row.List)
        {
            var result = await client.ListImportsAsync(target, maximumItems: 1000, cancellationToken: token);
            status = result.Status;
            if (result.IsSuccess) { values = result.Value.Items.Select(Value).ToArray(); complete = result.Value.IsComplete; }
        }
        else
        {
            var result = row.Action switch
            {
                ImportPermissionAction.Read => await client.GetImportAsync(target, token),
                ImportPermissionAction.Create => await client.CreateImportAsync(target, new("source-b", ImportPermissionContract.SourcePath(row, true), row.Project), false, authority, receipt!, token),
                ImportPermissionAction.Edit => await client.UpdateImportAsync(target, authority, receipt!, "source-b", ImportPermissionContract.SourcePath(row, true), 7.5, token),
                ImportPermissionAction.Delete => await client.DeleteImportAsync(target, authority, receipt!, cancellationToken: token),
                _ => throw new NativeCaseFailureException("contract-mismatch")
            };
            status = result.Status;
            if (result.IsSuccess) values = [Value(result.Value)];
        }
        return new(row, row.Action == ImportPermissionAction.Read ? tokens.Hash : mutationTokens.Hash, null,
            status, receipt?.Evidence, values, complete);
    }
}
