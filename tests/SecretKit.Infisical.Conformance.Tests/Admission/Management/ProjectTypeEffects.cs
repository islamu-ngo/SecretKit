using SecretKit.Core;
using SecretKit.Infisical.Management;
using SecretKit.TestFixtures;

namespace SecretKit.Infisical.Conformance.Tests;

internal static class ProjectTypeEffects
{
    internal static async ValueTask ExecuteAsync(ProjectFamilyContext c, IProjectTypeSource? source, CancellationToken token)
    {
        c.Probe.Contract(ProjectTypeContract.Owns(c.Definition.Key.Operation) &&
            ProjectTypeContract.Variants.Contains(c.Variant), NativeFailure.ContractMismatch);
        // A generic read-only lost-response case is not promoted by private input.
        if (!ProjectTypeContract.Cases.Contains(c.Definition.Key.Case))
        { c.Probe.Effect(NativeObservation.Unavailable); return; }
        var input = ProjectTypeInput.FromScope(c.Input);
        if (input is null) { c.Probe.Effect(NativeObservation.Unavailable); return; }
        var authorities = new ProjectTypeAuthorities(c.Required("setupIdentityId"), c.Required("runtimeIdentityId"),
            c.Required("deniedIdentityId"), c.Required("administrativeIdentityId"), c.Required("observerIdentityId"));
        source ??= new InfisicalProjectTypeSource(new(input.Observer), input.Observer.Identity);
        var root = new ProjectTypeRoot(Guid.NewGuid().ToString("N"), Guid.NewGuid().ToString("N"),
            c.Environment.Origin.AbsoluteUri, c.OrganizationId, c.Definition.Key.Operation, c.Variant,
            c.Definition.Key.Case, c.Definition.Key.Scope, input.ProviderRevision, input.Deployment, input.Epoch,
            input.Observer.Identity, source.Kind, authorities, ProjectTypeContract.Query(c.Variant));
        using var capability = SecretMaterial.FromText(input.Capability);
        var trial = await ProjectTypeTrial.OpenAsync(source, root, capability, input.TimeoutSeconds,
            owned => c.Cleanup(async _ => { await owned.DisposeAsync(); return true; }), token);
        await WitnessAsync("before");
        await trial.ArmAsync(token);
        var read = await OriginalAsync(c, root.Query, trial.OriginalPage, token);
        await trial.SettleAsync(read, token);
        await WitnessAsync("after");
        c.Probe.Effect(NativeObservation.Matched);

        async ValueTask WitnessAsync(string phase)
        {
            await trial.BeginAsync(phase, token);
            var access = new List<ProjectTypeAccess>();
            var full = await Read(NativeIdentityRole.Observer, new(null, true), true);
            var selected = await Read(NativeIdentityRole.Observer, root.Query, true);
            var runtime = await Read(NativeIdentityRole.Runtime, root.Query, true);
            _ = await Read(NativeIdentityRole.Denied, root.Query, false);
            var recheck = await Read(NativeIdentityRole.Observer, root.Query, true);
            await trial.ObserveAsync(phase, full!, [selected!, runtime!, recheck!], access.ToArray(), token);

            async ValueTask<ManagementPage<ProjectSummary>?> Read(NativeIdentityRole role, ProjectTypeQuery query, bool allowed)
            {
                // No secret material or process-local inventory cache is involved.
                using var transport = new ManagementTransport(c.Environment.Origin,
                    allowLoopbackDevelopmentHttp: c.Environment.AllowLoopbackDevelopmentHttp);
                var fresh = new ManagementClient(transport);
                using var request = ProjectOperations.ListProjects(c.OrganizationId, query.Type, query.IncludeRoles);
                var authority = c.Environment.CreateManagementAuthority(fresh, role, c.OrganizationId);
                var result = await fresh.ExecuteAsync(request, authority,
                    authority.IssueGrant(request.OperationId, request.Target), cancellationToken: token);
                c.Probe.Contract(allowed ? result.IsSuccess : result.Status == SecretStatus.Denied, NativeFailure.EffectMismatch);
                string actor = role switch
                {
                    NativeIdentityRole.Observer => authorities.Observer,
                    NativeIdentityRole.Runtime => authorities.Runtime,
                    _ => authorities.Denied
                };
                access.Add(new("", actor, c.OrganizationId, query, allowed));
                return result.IsSuccess ? result.Value : null;
            }
        }
    }

    private static async ValueTask<ProjectTypeReadResult> OriginalAsync(ProjectFamilyContext c,
        ProjectTypeQuery query, Func<ManagementPage<ProjectSummary>, bool> matches, CancellationToken token)
    {
        var client = c.Environment.CreateManagementClient();
        using var request = ProjectOperations.ListProjects(c.OrganizationId, query.Type, query.IncludeRoles);
        c.Probe.Contract(!request.IsMutation, NativeFailure.ContractMismatch);
        var role = c.Definition.Key.Case == "denied-authority" ? NativeIdentityRole.Denied : NativeIdentityRole.Administrative;
        using var cancellation = CancellationTokenSource.CreateLinkedTokenSource(token);
        bool presend = c.Definition.Key.Case == "cancellation-boundary";
        var barrier = presend ? new ProjectTokenBarrier(c.Environment.Tokens(role)) : null;
        var authority = new ManagementAuthority(client.Authority, barrier ?? c.Environment.Tokens(role), c.OrganizationId);
        Task? entered = barrier?.Entered;
        var execution = client.ExecuteAsync(request, authority, authority.IssueGrant(request.OperationId, request.Target),
            cancellationToken: cancellation.Token).AsTask();
        SecretOutcome<ManagementPage<ProjectSummary>>? result = null;
        bool cancelled = false;
        try
        {
            if (entered is not null)
            {
                await entered.WaitAsync(token); cancellation.Cancel(); barrier!.Release();
            }
            try { result = await execution; }
            catch (OperationCanceledException) when (!token.IsCancellationRequested && cancellation.IsCancellationRequested)
            { cancelled = true; }
            c.Probe.Contract(cancelled == presend && (cancelled ||
                (role == NativeIdentityRole.Denied ? result?.Status == SecretStatus.Denied :
                    result is { IsSuccess: true } success && matches(success.Value))), NativeFailure.ContractMismatch);
            return new(result?.Status, cancelled);
        }
        finally
        {
            cancellation.Cancel(); barrier?.Release();
            try { await execution; }
            catch (OperationCanceledException) { }
        }
    }
}
