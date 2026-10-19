using SecretKit.Core;
using SecretKit.Infisical.Management;
using SecretKit.TestFixtures;

namespace SecretKit.Infisical.Conformance.Tests;

// Parent integration: select only WorkloadTransitionContract.Owns definitions
// with a scoped workloadTransition input, before the old unavailable gate.
// Pass the optional source through native and generic registrars. Generic
// factory resolution must choose an owned variant explicitly, never erase the
// original generic label. No change to primary/rejected/trusted-IP gates.
internal static class WorkloadTransitionEffects
{
    internal static async ValueTask ExecuteAsync(IdentityAuthContext c, IWorkloadTransitionSource? source,
        CancellationToken token)
    {
        var input = WorkloadTransitionInput.FromScope(c.Core.Input);
        if (WorkloadTransitionContract.Gate(c.Definition, input) is not null)
        { c.Probe.Effect(NativeObservation.Unavailable); return; }
        var authorities = new WorkloadTransitionAuthorities(c.Required("setupIdentityId"), c.Required("runtimeIdentityId"),
            c.Required("deniedIdentityId"), c.Required("administrativeIdentityId"), c.Required("observerIdentityId"));
        source ??= new InfisicalWorkloadTransitionSource(new(input!.Observer), input.Observer.Identity);
        var root = new WorkloadTransitionRoot(Guid.NewGuid().ToString("N"), Guid.NewGuid().ToString("N"),
            c.Environment.Origin.AbsoluteUri, c.OrganizationId, c.Definition.Key.Operation, c.Variant,
            c.Definition.Key.Case, c.Definition.Key.Scope, source.Identity, source.Kind, authorities, input!.Profile);
        using var capability = SecretMaterial.FromText(input.Capability);
        var trial = await WorkloadTransitionTrial.OpenAsync(source, root, capability, input.TimeoutSeconds,
            owned => c.Core.Cleanup(async _ => { await owned.DisposeAsync(); return true; }), token);
        await WitnessAsync(c.Environment, root, trial, false, token);
        await trial.ArmAsync(token);
        var receipt = await DispatchAsync(c.Environment, root, trial.Issued, token);
        await trial.SettleAsync(receipt, token);
        await WitnessAsync(c.Environment, root, trial, true, token);
        c.Probe.Effect(trial.Outcome == WorkloadTransitionOutcome.Partial ?
            NativeObservation.Unavailable : NativeObservation.Matched);
    }

    internal static async ValueTask<WorkloadTransitionReceipt> DispatchAsync(NativeEnvironment env,
        WorkloadTransitionRoot root, WorkloadTransitionIssuance issued, CancellationToken token)
    {
        var intent = WorkloadTransitionContract.Intent(root, issued);
        bool attach = WorkloadTransitionContract.Attach(root);
        WorkloadAuthNullableText? template = intent.Template switch
        {
            WorkloadTransitionField.Value => WorkloadAuthNullableText.FromValue(issued.TemplateB),
            WorkloadTransitionField.Null => WorkloadAuthNullableText.Null(),
            _ => null
        };
        var direct = issued.TemplateConfigurationB;
        string? subject = attach && template is null ? direct.Subject : null;
        if (WorkloadTransitionContract.Mechanism(root) == "kubernetes")
        {
            using var reviewer = SecretMaterial.FromText(issued.ReviewerCredentialB);
            using var input = new KubernetesAuthConfigurationInput(
                allowedNames: attach ? direct.Subject : null, allowedNamespaces: attach ? "workload" : null,
                allowedAudience: attach ? issued.Audience : null,
                kubernetesHost: attach ? WorkloadAuthNullableText.FromValue(root.Origin + "review") : null,
                templateId: template, tokenReviewerJwt: intent.Reviewer == WorkloadTransitionField.Value ? reviewer : null,
                clearTokenReviewerJwt: intent.Reviewer == WorkloadTransitionField.Null,
                tokenReviewMode: attach ? KubernetesTokenReviewMode.Api : null,
                verifyTlsCertificate: attach ? true : null, policy: new(600, 1800, 2000));
            return await OriginalAsync(env, root, () => attach ?
                WorkloadIdentityAuthenticationOperations.AttachKubernetesAuth(root.Organization, issued.Target.Identity, input) :
                WorkloadIdentityAuthenticationOperations.UpdateKubernetesAuth(root.Organization, issued.Target.Identity, input), token);
        }
        if (WorkloadTransitionContract.Mechanism(root) == "oidc")
        {
            var input = new OidcAuthConfigurationInput(boundClaims: attach ? new Dictionary<string, string>() : null,
                oidcDiscoveryUrl: attach && template is null ? root.Origin + ".well-known/openid-configuration" : null,
                boundIssuer: attach && template is null ? issued.Issuer : null,
                boundAudiences: attach && template is null ? issued.Audience : null, boundSubject: subject,
                templateId: template, policy: new(600, 1800, 2000));
            return await OriginalAsync(env, root, () => attach ?
                WorkloadIdentityAuthenticationOperations.AttachOidcAuth(root.Organization, issued.Target.Identity, input) :
                WorkloadIdentityAuthenticationOperations.UpdateOidcAuth(root.Organization, issued.Target.Identity, input), token);
        }
        // Empty static keys remain an explicit primary gate. Constructing a legal
        // SDK input does not authorize fabricating an accepted native response.
        throw new NativeCaseFailureException("observer-unavailable");
    }

    internal static async ValueTask<WorkloadTransitionReceipt> OriginalAsync<T>(NativeEnvironment env,
        WorkloadTransitionRoot root, Func<ManagementRequest<T>> factory, CancellationToken token) where T : notnull
    {
        var client = env.CreateManagementClient();
        using var request = factory();
        var receipt = client.CreateReceipt(request);
        bool presend = root.Boundary == "cancellation-boundary", lost = root.Boundary == "lost-response-no-replay";
        var role = root.Boundary == "denied-authority" ? NativeIdentityRole.Denied : NativeIdentityRole.Administrative;
        var barrier = presend ? new ProjectTokenBarrier(env.Tokens(role)) : null;
        using var cancellation = CancellationTokenSource.CreateLinkedTokenSource(token);
        var authority = new ManagementAuthority(client.Authority, barrier ?? env.Tokens(role), root.Organization);
        using var boundary = lost ? new ProjectResponseBoundary(env.Origin, cancellation) : null;
        using var scope = boundary?.Enter();
        Task? entered = barrier?.Entered;
        var execution = client.ExecuteAsync(request, authority, authority.IssueGrant(request.OperationId, request.Target),
            receipt, cancellation.Token).AsTask();
        SecretOutcome<T>? result = null;
        bool cancelled = false;
        try
        {
            if (entered is not null)
            {
                await entered.WaitAsync(token);
                cancellation.Cancel(); barrier!.Release();
            }
            try { result = await execution; }
            catch (OperationCanceledException) when (cancellation.IsCancellationRequested && !token.IsCancellationRequested)
            { cancelled = true; }
            WorkloadTransitionContract.Require(!lost || boundary!.Reached, "effect-mismatch");
            if (result is { IsSuccess: true } success && success.Value is WorkloadAuthConfiguration config)
                WorkloadTransitionContract.Require(config.IdentityId == request.Target.ResourceId, "effect-mismatch");
            // Immutable snapshot of the actual original, never rewritten from
            // source settlement, even when a lost response was actually Applied.
            return new(receipt.Evidence, result?.Status, cancelled, request.Target.SecondaryId);
        }
        finally
        {
            cancellation.Cancel(); barrier?.Release();
            try { result ??= await execution; }
            catch (OperationCanceledException) { }
            if (result is { IsSuccess: true } owned && owned.Value is IDisposable disposable) disposable.Dispose();
        }
    }

    internal static async ValueTask WitnessAsync(NativeEnvironment env, WorkloadTransitionRoot root,
        WorkloadTransitionTrial trial, bool after, CancellationToken token)
    {
        string phase = after ? "after" : "before";
        await trial.BeginAsync(phase, token);
        var issued = trial.Issued;
        var attempts = new List<WorkloadTransitionAttempt>();
        foreach (string name in new[] { "old", "new", "wrong", "old", "new", "control" })
        {
            bool control = name == "control";
            var principal = control ? issued.Control : issued.Target;
            var input = issued.Proofs.Single(p => p.Name == (control ? "new" : name));
            bool allowed = trial.Allowed(principal.Identity, input, after);
            using var jwt = SecretMaterial.FromText(input.Jwt);
            using var proof = WorkloadTransitionContract.Mechanism(root) switch
            {
                "kubernetes" => InfisicalLoginProof.Kubernetes(principal.Identity, jwt),
                "oidc" => InfisicalLoginProof.Oidc(principal.Identity, jwt),
                _ => InfisicalLoginProof.Jwt(principal.Identity, jwt)
            };
            using var auth = new InfisicalProofAuthentication(env.Origin,
                new InfisicalNetworkOptions { AllowLoopbackDevelopmentHttp = env.AllowLoopbackDevelopmentHttp });
            var receipt = auth.CreateReceipt();
            var result = await auth.LoginAsync(proof, receipt, token);
            using var login = result.IsSuccess ? result.Value : null;
            WorkloadTransitionContract.Require(allowed ? result.IsSuccess && receipt.Evidence == DispatchEvidence.Applied &&
                login!.ExpiresIn == 600 && login.AccessTokenMaxTTL == 1800 :
                result.Status == SecretStatus.Denied && receipt.Evidence == DispatchEvidence.Rejected, "effect-mismatch");
            var reads = new List<WorkloadTransitionRead>();
            string? hash = null;
            if (login is not null)
            {
                hash = WorkloadTransitionContract.Hash(login.Token.Material.Reveal());
                foreach (var canary in new[] { issued.Target, issued.Control })
                {
                    bool readAllowed = canary.Identity == principal.Identity;
                    await ReadAsync(env, login.Token.Material, canary, readAllowed, token);
                    reads.Add(new(hash, principal.Identity, canary.Project, canary.CanaryKey, readAllowed));
                }
            }
            attempts.Add(new(principal.Identity, WorkloadTransitionContract.Hash(input.Jwt), allowed, hash, reads.ToArray()));
        }
        var controls = new List<WorkloadTransitionRead>();
        foreach (var role in new[] { NativeIdentityRole.Runtime, NativeIdentityRole.Denied, NativeIdentityRole.Observer })
        {
            var result = await env.Tokens(role).GetTokenAsync(token);
            WorkloadTransitionContract.Require(result.IsSuccess, "missing-input");
            using var credential = result.Value;
            bool allowed = role == NativeIdentityRole.Observer;
            await ReadAsync(env, credential.Material, issued.Target, allowed, token);
            string identity = role == NativeIdentityRole.Runtime ? root.Authorities.Runtime :
                role == NativeIdentityRole.Denied ? root.Authorities.Denied : root.Authorities.Observer;
            controls.Add(new(WorkloadTransitionContract.Hash(credential.Material.Reveal()), identity,
                issued.Target.Project, issued.Target.CanaryKey, allowed));
        }
        await trial.ObserveAsync(phase, attempts.ToArray(), controls.ToArray(), token);
    }
    internal static async ValueTask ReadAsync(NativeEnvironment env, SecretMaterial material,
        WorkloadTransitionPrincipal canary, bool allowed, CancellationToken token)
    {
        await using var client = new InfisicalClient(env.Origin, new Tokens(material),
            new InfisicalNetworkOptions { AllowLoopbackDevelopmentHttp = env.AllowLoopbackDevelopmentHttp });
        var result = await client.ReadAsync(new(client.Authority,
            new InfisicalSecretAddress(canary.Project, "witness", "/", canary.CanaryKey)), token);
        using var read = result.IsSuccess ? result.Value : null;
        WorkloadTransitionContract.Require(allowed ? read is not null && read.Material.Reveal() == canary.CanaryValue :
            result.Status == SecretStatus.Denied, "effect-mismatch");
    }
    private sealed class Tokens(SecretMaterial material) : IInfisicalTokenSource
    {
        public ValueTask<SecretOutcome<InfisicalAccessToken>> GetTokenAsync(CancellationToken token)
        {
            token.ThrowIfCancellationRequested();
            return ValueTask.FromResult(SecretOutcome<InfisicalAccessToken>.Success(new(material.Copy())));
        }
    }
}
