using SecretKit.Core;
using SecretKit.Infisical.Management;
using SecretKit.TestFixtures;

namespace SecretKit.Infisical.Conformance.Tests;

public sealed class InfisicalWorkloadTransitionCalibrationTests
{
    public static IEnumerable<(string Operation, string Variant, string Boundary)> Cases() =>
        InfisicalWorkloadTransitionGateTests.Cases().Where(c => c.Variant != "publicKeys.empty");
    internal static WorkloadTransitionProfile Profile() => new("controlled-workload-v1", "controlled-deployment",
        "controlled-epoch", WorkloadTransitionContract.Journals.Select(j => new WorkloadTransitionJournal(j,
            "controlled-" + j + "-writer", j + "-v1")).ToArray(), true, true, true);
    internal static WorkloadTransitionInput Input() => new(new(new("https://workload-source.invalid/"),
        "source-channel-token", "controlled-workload-source", 15), "workload-capability", Profile(), 15);
    internal static object Families() => new Dictionary<string, object>
    {
        ["C08-IM-WorkloadIdentityAuthentication"] = Scope(),
        ["C08-IM-ManagementClient"] = Scope()
    };
    private static object Scope() => new
    {
        scopes = new
        {
            local = new
            {
                organizationId = InfisicalWorkloadTransitionFixture.Organization,
                apiRevision = "AuthV1IdentitiesV1SecretsV4",
                setupIdentityId = InfisicalWorkloadTransitionFixture.Authorities.Setup,
                runtimeIdentityId = InfisicalWorkloadTransitionFixture.Authorities.Runtime,
                deniedIdentityId = InfisicalWorkloadTransitionFixture.Authorities.Denied,
                administrativeIdentityId = InfisicalWorkloadTransitionFixture.Authorities.Administrative,
                observerIdentityId = InfisicalWorkloadTransitionFixture.Authorities.Observer,
                workloadTransition = Input()
            }
        }
    };
    internal static NativeCaseDefinition Definition(string operation, string variant, string boundary) =>
        new(new("Infisical", operation, variant, "local", boundary),
            InfisicalIdentityAuthenticationFamilies.Bindings[operation].Member);
    internal static WorkloadTransitionRoot Root(NativeEnvironment env, string operation, string variant, string boundary) =>
        new(Guid.NewGuid().ToString("N"), Guid.NewGuid().ToString("N"), env.Origin.AbsoluteUri,
            InfisicalWorkloadTransitionFixture.Organization, operation, variant, boundary, "local",
            "controlled-workload-source", WorkloadTransitionSourceKind.ControlledFixture,
            InfisicalWorkloadTransitionFixture.Authorities, Profile());

    [Test]
    public async Task CatalogRetainsTwelveFactoriesAndTwentyFourOptionalPairs()
    {
        var bindings = InfisicalIdentityAuthenticationFamilies.Bindings.Where(p =>
            p.Key.StartsWith(WorkloadTransitionContract.Prefix, StringComparison.Ordinal)).ToArray();
        await Assert.That(bindings.Length).IsEqualTo(12);
        await Assert.That(bindings.Sum(b => b.Value.Variants.Length)).IsEqualTo(256);
        await Assert.That(bindings.Sum(b => b.Value.Variants.Length * (b.Value.Mutation ? 5 : 4))).IsEqualTo(1266);
        await Assert.That(Cases().Count()).IsEqualTo(110);
        await Assert.That(InfisicalWorkloadTransitionGateTests.Cases().Count()).IsEqualTo(120);
    }
    [Test]
    [Arguments(true)]
    [Arguments(false)]
    public async Task EmptyStaticFactoriesRemainUnsentWithoutNativeAcceptance(bool attach)
    {
        var input = new JwtAuthConfigurationInput(JwtAuthConfigurationType.Static, publicKeys: [],
            boundClaims: new Dictionary<string, string>());
        using var request = attach ?
            WorkloadIdentityAuthenticationOperations.AttachJwtAuth(InfisicalWorkloadTransitionFixture.Organization,
                "20000000-0000-0000-0000-000000000002", input) :
            WorkloadIdentityAuthenticationOperations.UpdateJwtAuth(InfisicalWorkloadTransitionFixture.Organization,
                "20000000-0000-0000-0000-000000000002", input);
        var d = Definition(WorkloadTransitionContract.Prefix + (attach ? "AttachJwtAuth" : "UpdateJwtAuth"),
            "publicKeys.empty", "independent-effect");
        await Assert.That(request.IsMutation).IsTrue();
        await Assert.That(WorkloadTransitionContract.Gate(d, Input())).IsNotNull();
        await Assert.That(input.PublicKeys!.Count).IsEqualTo(0);
    }
    [Test]
    [MethodDataSource(nameof(Cases))]
    public async Task DirectSdkAndIndependentSourceCalibrateBeforeEffectFaults(string operation, string variant, string boundary)
    {
        await using var provider = new InfisicalWorkloadTransitionFixture();
        using var env = provider.Environment(Families());
        await DirectAsync(provider, env, operation, variant, boundary);
        await Assert.That(provider.Originals).IsEqualTo(boundary == "cancellation-boundary" ? 0 : 1);
        await Assert.That(provider.Source.Opens).IsEqualTo(1);
        await Assert.That(provider.Source.Closes).IsEqualTo(1);
        await Assert.That(provider.Remaining).IsEqualTo(0);
        await Assert.That(provider.BorrowedPreserved).IsTrue();
        await Assert.That(provider.Copies.All(b => b.All(v => v == 0))).IsTrue();
        await Assert.That(provider.Reviews.Count).IsEqualTo(12);
        await Assert.That(provider.Ingress.Count(i => i.Intent is null)).IsEqualTo(12);
    }

    internal static async Task DirectAsync(InfisicalWorkloadTransitionFixture provider, NativeEnvironment env,
        string operation, string variant, string boundary)
    {
        var root = Root(env, operation, variant, boundary);
        using var capability = SecretMaterial.FromText("workload-capability");
        WorkloadTransitionTrial? retained = null;
        using var deadline = new CancellationTokenSource(TimeSpan.FromSeconds(15));
        try
        {
            var trial = await WorkloadTransitionTrial.OpenAsync(provider.Source.CreateClient(), root, capability, 15,
                t => retained = t, deadline.Token);
            await DirectProofs(false);
            await trial.ArmAsync(deadline.Token);
            bool attach = operation.Contains(".Attach", StringComparison.Ordinal);
            var issued = trial.Issued;
            WorkloadAuthNullableText? template = variant.EndsWith("templateId.value", StringComparison.Ordinal) ?
                WorkloadAuthNullableText.FromValue(issued.TemplateB) :
                variant == "templateId.null" ? WorkloadAuthNullableText.Null() : null;
            WorkloadTransitionReceipt receipt;
            if (operation.Contains("Kubernetes", StringComparison.Ordinal))
            {
                using var reviewer = SecretMaterial.FromText(issued.ReviewerCredentialB);
                using var input = new KubernetesAuthConfigurationInput(
                    allowedNames: attach ? "workload-subject" : null, allowedNamespaces: attach ? "workload" : null,
                    allowedAudience: attach ? "workload-audience" : null,
                    kubernetesHost: attach ? WorkloadAuthNullableText.FromValue(env.Origin.AbsoluteUri + "review") : null,
                    templateId: template,
                    tokenReviewerJwt: variant.EndsWith("tokenReviewerJwt.value", StringComparison.Ordinal) ? reviewer : null,
                    clearTokenReviewerJwt: variant == "reviewerJwt.null" || variant.EndsWith("clearTokenReviewerJwt.true", StringComparison.Ordinal),
                    tokenReviewMode: attach ? KubernetesTokenReviewMode.Api : null,
                    verifyTlsCertificate: attach ? true : null, policy: new(600, 1800, 2000));
                receipt = await Send(() => attach ?
                    WorkloadIdentityAuthenticationOperations.AttachKubernetesAuth(root.Organization, issued.Target.Identity, input) :
                    WorkloadIdentityAuthenticationOperations.UpdateKubernetesAuth(root.Organization, issued.Target.Identity, input));
            }
            else
            {
                var input = new OidcAuthConfigurationInput(boundClaims: attach ? new Dictionary<string, string>() : null,
                    oidcDiscoveryUrl: attach && template is null ? env.Origin.AbsoluteUri + ".well-known/openid-configuration" : null,
                    boundIssuer: attach && template is null ? issued.Issuer : null,
                    boundAudiences: attach && template is null ? "workload-audience" : null,
                    boundSubject: attach && template is null ? "workload-subject" : null,
                    templateId: template, policy: new(600, 1800, 2000));
                receipt = await Send(() => attach ?
                    WorkloadIdentityAuthenticationOperations.AttachOidcAuth(root.Organization, issued.Target.Identity, input) :
                    WorkloadIdentityAuthenticationOperations.UpdateOidcAuth(root.Organization, issued.Target.Identity, input));
            }
            await trial.SettleAsync(receipt, deadline.Token);
            await DirectProofs(true);

            async ValueTask<WorkloadTransitionReceipt> Send<T>(Func<ManagementRequest<T>> factory) where T : notnull
            {
                var client = env.CreateManagementClient();
                using var request = factory();
                var original = client.CreateReceipt(request);
                var role = boundary == "denied-authority" ? NativeIdentityRole.Denied : NativeIdentityRole.Administrative;
                var barrier = boundary == "cancellation-boundary" ? new ProjectTokenBarrier(env.Tokens(role)) : null;
                using var cancellation = CancellationTokenSource.CreateLinkedTokenSource(deadline.Token);
                var auth = new ManagementAuthority(client.Authority, barrier ?? env.Tokens(role), root.Organization);
                using var loss = boundary == "lost-response-no-replay" ? new ProjectResponseBoundary(env.Origin, cancellation) : null;
                using var scope = loss?.Enter();
                Task? entered = barrier?.Entered;
                var execution = client.ExecuteAsync(request, auth, auth.IssueGrant(request.OperationId, request.Target),
                    original, cancellation.Token).AsTask();
                SecretOutcome<T>? result = null;
                bool cancelled = false;
                try
                {
                    if (entered is not null)
                    { await entered.WaitAsync(deadline.Token); cancellation.Cancel(); barrier!.Release(); }
                    try { result = await execution; }
                    catch (OperationCanceledException) when (!deadline.IsCancellationRequested) { cancelled = true; }
                    await Assert.That(loss is null || loss.Reached).IsTrue();
                    return new(original.Evidence, result?.Status, cancelled, request.Target.SecondaryId);
                }
                finally
                {
                    cancellation.Cancel(); barrier?.Release();
                    try { result ??= await execution; } catch (OperationCanceledException) { }
                    if (result is { IsSuccess: true } owned && owned.Value is IDisposable disposable) disposable.Dispose();
                }
            }
            async Task DirectProofs(bool after)
            {
                string phase = after ? "after" : "before";
                await trial.BeginAsync(phase, deadline.Token);
                var packet = trial.Issued;
                var attempts = new List<WorkloadTransitionAttempt>();
                bool applied = after && boundary is not ("denied-authority" or "cancellation-boundary");
                bool initialAttached = !operation.Contains(".Attach", StringComparison.Ordinal);
                bool newKey = applied && (!initialAttached || variant.EndsWith("templateId.value", StringComparison.Ordinal) ||
                    variant.EndsWith("tokenReviewerJwt.value", StringComparison.Ordinal));
                foreach (string name in new[] { "old", "new", "wrong", "old", "new", "control" })
                {
                    bool control = name == "control";
                    var principal = control ? packet.Control : packet.Target;
                    string proofName = control ? "new" : name;
                    var signed = packet.Proofs.Single(p => p.Name == proofName);
                    bool allowed = control || (initialAttached || applied) && proofName == (newKey ? "new" : "old");
                    using var jwt = SecretMaterial.FromText(signed.Jwt);
                    using var proof = operation.Contains("Kubernetes", StringComparison.Ordinal) ?
                        InfisicalLoginProof.Kubernetes(principal.Identity, jwt) : InfisicalLoginProof.Oidc(principal.Identity, jwt);
                    using var authentication = new InfisicalProofAuthentication(env.Origin,
                        new InfisicalNetworkOptions { AllowLoopbackDevelopmentHttp = true });
                    var receipt = authentication.CreateReceipt();
                    var result = await authentication.LoginAsync(proof, receipt, deadline.Token);
                    using var login = result.IsSuccess ? result.Value : null;
                    await Assert.That(allowed ? result.IsSuccess && receipt.Evidence == DispatchEvidence.Applied :
                        result.Status == SecretStatus.Denied && receipt.Evidence == DispatchEvidence.Rejected).IsTrue();
                    var reads = new List<WorkloadTransitionRead>();
                    string? hash = null;
                    if (login is not null)
                    {
                        hash = WorkloadTransitionContract.Hash(login.Token.Material.Reveal());
                        foreach (var canary in new[] { packet.Target, packet.Control })
                        {
                            bool readable = canary.Identity == principal.Identity;
                            await DirectRead(login.Token.Material, canary, readable);
                            reads.Add(new(hash, principal.Identity, canary.Project, canary.CanaryKey, readable));
                        }
                    }
                    attempts.Add(new(principal.Identity, WorkloadTransitionContract.Hash(signed.Jwt), allowed, hash, reads.ToArray()));
                }
                var controls = new List<WorkloadTransitionRead>();
                foreach (var role in new[] { NativeIdentityRole.Runtime, NativeIdentityRole.Denied, NativeIdentityRole.Observer })
                {
                    var result = await env.Tokens(role).GetTokenAsync(deadline.Token);
                    using var credential = result.Value;
                    bool allowed = role == NativeIdentityRole.Observer;
                    await DirectRead(credential.Material, packet.Target, allowed);
                    controls.Add(new(WorkloadTransitionContract.Hash(credential.Material.Reveal()),
                        role == NativeIdentityRole.Runtime ? root.Authorities.Runtime :
                            role == NativeIdentityRole.Denied ? root.Authorities.Denied : root.Authorities.Observer,
                        packet.Target.Project, packet.Target.CanaryKey, allowed));
                }
                await trial.ObserveAsync(phase, attempts.ToArray(), controls.ToArray(), deadline.Token);
            }
            async Task DirectRead(SecretMaterial material, WorkloadTransitionPrincipal canary, bool allowed)
            {
                await using var client = new InfisicalClient(env.Origin, new DirectTokens(material),
                    new InfisicalNetworkOptions { AllowLoopbackDevelopmentHttp = true });
                var result = await client.ReadAsync(new(client.Authority,
                    new InfisicalSecretAddress(canary.Project, "witness", "/", canary.CanaryKey)), deadline.Token);
                using var read = result.IsSuccess ? result.Value : null;
                await Assert.That(allowed ? read?.Material.Reveal() == canary.CanaryValue : result.Status == SecretStatus.Denied).IsTrue();
            }
        }
        finally { if (retained is not null) await retained.DisposeAsync(); }
    }
    private sealed class DirectTokens(SecretMaterial material) : IInfisicalTokenSource
    {
        public ValueTask<SecretOutcome<InfisicalAccessToken>> GetTokenAsync(CancellationToken token)
        {
            token.ThrowIfCancellationRequested();
            return ValueTask.FromResult(SecretOutcome<InfisicalAccessToken>.Success(new(material.Copy())));
        }
    }
}
