using SecretKit.Core;
using SecretKit.TestFixtures;

namespace SecretKit.Infisical.Conformance.Tests;

// Authority decision:
// IInfisicalTokenSource explicitly supplies a host-selected independent copy on
// EACH dispatch (InfisicalAuthentication.cs; InfisicalDynamicDispatchHandler).
// It does not bind a principal to a client instance. The client binds origin,
// scope and definition ownership. We preserve those bindings unchanged.
//
// This private caller performs at most one Setup inspection, awaits its COMPLETE
// SDK operation (whose using token has disposed its copy), then irreversibly
// seals to one explicitly supplied exercising source. It never chooses a source
// in response to denial; no retry, fallback, replay or client/definition forgery.
// Setup is not a permission granted to Runtime. The authenticated provider
// ingress MUST corroborate the bootstrap principal and the measured principal.
// The client is private, never escapes this method, and no operation overlaps
// sealing. Setup after sealing, duplicate measurement, failed bootstrap reuse,
// and concurrent token-source transitions all fail closed.
internal sealed class DynamicPermissionTokens : IInfisicalTokenSource, IDisposable
{
    private readonly object gate = new();
    private IInfisicalTokenSource? setup, measured;
    private int phase;
    private bool busy, disposed;
    internal string? SetupHash { get; private set; }
    internal string MeasuredHash { get; private set; } = "";
    internal DynamicPermissionTokens(IInfisicalTokenSource? setup, IInfisicalTokenSource measured)
    { this.setup = setup; this.measured = measured; phase = setup is null ? 1 : 0; }
    internal void Seal()
    {
        lock (gate)
        {
            DynamicPermissionContract.Require(!disposed && !busy && phase == 1);
            setup = null;
            phase = 2;
        }
    }
    public async ValueTask<SecretOutcome<InfisicalAccessToken>> GetTokenAsync(CancellationToken token)
    {
        IInfisicalTokenSource source;
        bool bootstrap;
        lock (gate)
        {
            token.ThrowIfCancellationRequested();
            DynamicPermissionContract.Require(!disposed && !busy && phase is 0 or 2);
            bootstrap = phase == 0;
            source = (bootstrap ? setup : measured)!;
            busy = true;
            phase = 4; // Any failure consumes this phase; there is no recovery to Setup.
        }
        try
        {
            var outcome = await source.GetTokenAsync(token);
            if (!outcome.IsSuccess) return outcome;
            try
            {
                token.ThrowIfCancellationRequested();
                string hash = DynamicPermissionContract.Hash(outcome.Value.Material.Reveal());
                lock (gate)
                {
                    DynamicPermissionContract.Require(!disposed);
                    if (bootstrap) { SetupHash = hash; phase = 1; }
                    else { MeasuredHash = hash; phase = 3; }
                }
                return outcome;
            }
            catch { outcome.Value.Dispose(); throw; }
        }
        finally { lock (gate) busy = false; }
    }
    public void Dispose()
    {
        lock (gate) { disposed = true; phase = 4; setup = measured = null; }
    }
}
internal static class DynamicPermissionClient
{
    internal static async ValueTask<DynamicPermissionAttempt> ExecuteAsync(NativeEnvironment env,
        DynamicPermissionRoot root, DynamicPermissionTrial trial, DynamicPermissionRow row, bool after,
        CancellationToken token)
    {
        NativeIdentityRole role = row.Principal == root.Authorities.Runtime ? NativeIdentityRole.Runtime :
            row.Principal == root.Authorities.Denied ? NativeIdentityRole.Denied :
            row.Principal == root.Authorities.Observer ? NativeIdentityRole.Observer :
            throw new SecretKit.TestFixtures.NativeCaseFailureException("missing-input");
        using var tokens = new DynamicPermissionTokens(DynamicPermissionContract.Bootstrap(row.Action) ?
            env.Tokens(NativeIdentityRole.Setup) : null, env.Tokens(role));
        await using var client = new InfisicalDynamicClient(env.Origin, tokens,
            new(row.Slug, row.Environment, row.Path, row.Folder),
            new InfisicalNetworkOptions { AllowLoopbackDevelopmentHttp = env.AllowLoopbackDevelopmentHttp });
        var target = client.Definition(row.Name);
        InfisicalDynamicDefinition? bound = null;
        if (DynamicPermissionContract.Bootstrap(row.Action))
        {
            var bootstrap = await client.InspectDefinitionAsync(target, token);
            DynamicPermissionContract.Require(bootstrap.IsSuccess && bootstrap.Value.Id == row.Definition, "effect-mismatch");
            bound = bootstrap.Value;
        }
        tokens.Seal();
        SecretStatus status;
        InfisicalDynamicMutationReceipt? receipt = null;
        Guid? leaseId = null; string? material = null;
        switch (row.Action)
        {
            case DynamicPermissionAction.Read:
                var read = await client.InspectDefinitionAsync(target, token);
                status = read.Status;
                DynamicPermissionContract.Require(!read.IsSuccess || read.Value.Id == row.Definition, "effect-mismatch");
                break;
            case DynamicPermissionAction.Create:
                using (var profile = trial.Issued.Sql.Create())
                {
                    receipt = new(target, InfisicalDynamicOperation.CreateDefinition);
                    var create = await client.CreateDefinitionAsync(target, profile, new(TimeSpan.FromSeconds(300)),
                        new(TimeSpan.FromSeconds(600)), receipt, token);
                    status = create.Status;
                    DynamicPermissionContract.Require(!create.IsSuccess || create.Value.Id == row.Definition, "effect-mismatch");
                }
                break;
            case DynamicPermissionAction.Edit:
                receipt = new(target, InfisicalDynamicOperation.UpdateDefinition);
                var edit = await client.UpdateDefinitionAsync(bound!, new NativeDynamicDefinitionPatch(
                    defaultTtl: new(TimeSpan.FromSeconds(240))), receipt, token);
                status = edit.Status;
                DynamicPermissionContract.Require(!edit.IsSuccess || edit.Value.Id == row.Definition &&
                    edit.Value.DefaultTtl.Duration == TimeSpan.FromSeconds(240), "effect-mismatch");
                break;
            case DynamicPermissionAction.Delete:
                receipt = new(target, InfisicalDynamicOperation.DeleteDefinition);
                status = (await client.DeleteDefinitionAsync(bound!, receipt, cancellationToken: token)).Status;
                break;
            case DynamicPermissionAction.Lease:
                receipt = new(target, InfisicalDynamicOperation.Acquire);
                var acquired = await client.AcquireDatabaseAsync(bound!, receipt, cancellationToken: token);
                status = acquired.Status;
                using (var lease = acquired.IsSuccess ? acquired.Value : null)
                {
                    if (lease is not null)
                    {
                        var copied = lease.CopyCredentials();
                        DynamicPermissionContract.Require(copied.IsSuccess, "effect-mismatch");
                        using var credentials = copied.Value;
                        // These deliberate exports are ordinary strings, NOT erased by disposal.
                        string username = credentials.RevealUsername(), password = credentials.RevealPassword();
                        leaseId = lease.Reference.Id;
                        material = DynamicPermissionContract.MaterialHash(username, password);
                        foreach (var action in Enum.GetValues<DynamicPermissionSqlAction>())
                            await trial.MeasureAsync(leaseId.Value, row, username, password, action, after, token);
                    }
                }
                break;
            default: throw new SecretKit.TestFixtures.NativeCaseFailureException("contract-mismatch");
        }
        return new(row, tokens.MeasuredHash, tokens.SetupHash, status, receipt?.Evidence, leaseId, material);
    }
}
