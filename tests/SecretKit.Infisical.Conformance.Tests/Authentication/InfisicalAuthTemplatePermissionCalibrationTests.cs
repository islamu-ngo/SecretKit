using SecretKit.Core;
using SecretKit.Infisical.Management;
using SecretKit.TestFixtures;

namespace SecretKit.Infisical.Conformance.Tests;

// Deliberately independent of Effects/Trial and their dispatch helpers.
public sealed class InfisicalAuthTemplatePermissionCalibrationTests
{
    public static IEnumerable<(string Operation, int Action, string Boundary, bool Generic)> Cases() =>
        InfisicalAuthTemplatePermissionEffectTests.Cases().Where(c => c.Action != (int)AuthTemplatePermissionAction.Unlink);
    [Test]
    [MethodDataSource(nameof(Cases))]
    public async Task DirectSdkGrantAndTemplateOperationsCalibrateTheCompleteBoundary(string operation, int action, string boundary, bool generic)
    {
        await using var fixture = new InfisicalAuthTemplatePermissionFixture();
        using var env = fixture.Environment(operation, (AuthTemplatePermissionAction)action);
        var root = fixture.Root(operation, (AuthTemplatePermissionAction)action, boundary);
        var source = fixture.Source.CreateClient(); var plan = new AuthTemplatePermissionPlan(root);
        using var verifier = new AuthTemplatePermissionVerifier(root);
        using var capability = SecretMaterial.FromText("auth-template-capability");
        using var deadline = new CancellationTokenSource(TimeSpan.FromSeconds(30));
        AuthTemplatePermissionIssued? issued = null;
        bool applied = boundary is not ("denied-authority" or "cancellation-boundary");
        bool create = operation.EndsWith(".CreateOrganizationRole", StringComparison.Ordinal);
        try
        {
            await Step(AuthTemplatePermissionStep.Reserve, capability);
            await Assert.That(fixture.Generated).IsEqualTo(0);
            await Step(AuthTemplatePermissionStep.Open);
            await Assert.That(issued!.Actors.All(a => a.Identity.Owned && !root.Authorities.All.Contains(a.Identity.Principal))).IsTrue();
            await Assert.That(issued.Actors.Select(a => a.Identity.Principal).Distinct().Count()).IsEqualTo(5);
            await Assert.That(issued.Actors[4].Identity.Organization != root.Organization).IsTrue();
            await Step(AuthTemplatePermissionStep.Before); await Exercise(false); await Step(AuthTemplatePermissionStep.ObserveBefore);
            await Step(AuthTemplatePermissionStep.Arm);
            OrganizationRoleAction grant = (AuthTemplatePermissionAction)action switch
            {
                AuthTemplatePermissionAction.List => OrganizationRoleAction.ListTemplates,
                AuthTemplatePermissionAction.Create => OrganizationRoleAction.CreateTemplates,
                AuthTemplatePermissionAction.Edit => OrganizationRoleAction.EditTemplates,
                AuthTemplatePermissionAction.Delete => OrganizationRoleAction.DeleteTemplates,
                AuthTemplatePermissionAction.Attach => OrganizationRoleAction.AttachTemplates,
                _ => throw new InvalidOperationException()
            };
            var change = new OrganizationRoleChange(plan.Slug, plan.Slug,
                permissions: [new(OrganizationRoleSubject.MachineIdentityAuthTemplate, grant)]);
            var original = await Send(create ? RoleChangeOperations.CreateOrganizationRole(root.Organization, change) :
                RoleChangeOperations.UpdateOrganizationRole(root.Organization, issued.Id("policy"), change));
            await Step(AuthTemplatePermissionStep.Settle);
            var expectedEvidence = boundary switch
            {
                "cancellation-boundary" => DispatchEvidence.NotDispatched,
                "denied-authority" => DispatchEvidence.Rejected,
                "lost-response-no-replay" => DispatchEvidence.PossiblyDispatched,
                _ => DispatchEvidence.Applied
            };
            await Assert.That(original.Native.Evidence).IsEqualTo(expectedEvidence);
            var originals = verifier.Requests.Where(r => r.Phase == "original").ToArray();
            await Assert.That(originals.Length).IsEqualTo(boundary == "cancellation-boundary" ? 0 : 1);
            var grants = verifier.PolicyChanges.Where(c => c.Request != "bootstrap").ToArray();
            await Assert.That(grants.Length).IsEqualTo(applied ? 1 : 0);
            if (applied)
            {
                await Assert.That(grants[0].After!.Subject).IsEqualTo("machine-identity-auth-template");
                await Assert.That(grants[0].After!.Actions.SequenceEqual([((AuthTemplatePermissionAction)action).ToString().ToLowerInvariant() + "-templates"])).IsTrue();
                await Assert.That(grants[0].After!.Configuration).IsEqualTo(originals.Single().BodyHash);
                _ = await Send(OrganizationMembershipOperations.UpdateOrganizationMembership(root.Organization, issued.Id("member-0"), plan.Slug), true);
            }
            await Step(AuthTemplatePermissionStep.After); await Exercise(true); await Step(AuthTemplatePermissionStep.ObserveAfter);
            foreach (var state in verifier.Inventory.Where(s => s.Organization == root.Organization))
            {
                var client = env.CreateManagementClient();
                using var get = IdentityTemplateOperations.GetIdentityTemplate(root.Organization, state.Id);
                var authority = new ManagementAuthority(client.Authority, env.Tokens(NativeIdentityRole.Observer), root.Organization);
                var observed = await client.ExecuteAsync(get, authority, authority.IssueGrant(get.OperationId, get.Target), cancellationToken: deadline.Token);
                await Assert.That(observed.IsSuccess && observed.Value.Name == state.Name && observed.Value.Configuration.AllowedAudience == state.Configuration.Audience &&
                    observed.Value.Configuration.TokenReviewMode == "api" && observed.Value.Configuration.KubernetesHost == "https://kubernetes.example.invalid" &&
                    observed.Value.Configuration.VerifyTlsCertificate == false && observed.Value.HasStoredCredential == false).IsTrue();
            }
            var peer = verifier.Inventory.Single(s => s.Id == issued.Id("peer"));
            await Assert.That(peer.Name).IsEqualTo("auth-peer-" + root.Nonce);
            await Assert.That(peer.Revision).IsEqualTo(1);
            if (applied && (AuthTemplatePermissionAction)action == AuthTemplatePermissionAction.Delete)
            {
                await Assert.That(verifier.Inventory.Any(s => s.Id == issued.Id("selected"))).IsFalse();
                var client = env.CreateManagementClient();
                using var get = IdentityTemplateOperations.GetIdentityTemplate(root.Organization, issued.Id("selected"));
                var observer = new ManagementAuthority(client.Authority, env.Tokens(NativeIdentityRole.Observer), root.Organization);
                var absent = await client.ExecuteAsync(get, observer, observer.IssueGrant(get.OperationId, get.Target), cancellationToken: deadline.Token);
                await Assert.That(absent.Status).IsEqualTo(SecretStatus.Absent);
            }
            if (applied && (AuthTemplatePermissionAction)action == AuthTemplatePermissionAction.Create)
                await Assert.That(verifier.Inventory.Single(s => s.Id == issued.Id("created")).Name).IsEqualTo("auth-created-" + root.Nonce);
            await Assert.That(original.Native.Evidence).IsEqualTo(expectedEvidence);
            await Assert.That(fixture.Originals).IsEqualTo(boundary == "cancellation-boundary" ? 0 : 1);
            if (generic) await Assert.That(InfisicalGovernanceFamilies.Bindings[InfisicalAuthTemplatePermissionEffectTests.Execute].Variants.Contains("factory." + operation)).IsTrue();
        }
        finally
        {
            try { await Step(AuthTemplatePermissionStep.Close); }
            finally { issued?.Erase(); }
        }
        await InfisicalAuthTemplatePermissionEffectTests.Clean(fixture);
        async Task Step(AuthTemplatePermissionStep step, SecretMaterial? cap = null)
        {
            var packet = await source.StepAsync(root, step, cap, deadline.Token);
            if (step == AuthTemplatePermissionStep.Open) issued = new([], packet.Actors);
            verifier.Check(packet, step);
            if (issued is not null) issued = issued with { Bindings = verifier.Bindings };
        }
        async Task Exercise(bool after)
        {
            foreach (var row in plan.Rows())
            {
                using var tokens = new MemberPermissionTokens(issued!.Actors[row.Actor].Credential);
                var client = env.CreateManagementClient();
                var authority = new ManagementAuthority(client.Authority, tokens, root.Organization);
                bool allowed = after && applied && row.Control == "selected";
                switch (row.Action)
                {
                    case AuthTemplatePermissionAction.List:
                        using (var request = IdentityTemplateOperations.SearchIdentityTemplates(root.Organization, limit: 100))
                        {
                            var result = await client.ExecuteAsync(request, authority, authority.IssueGrant(request.OperationId, request.Target), cancellationToken: deadline.Token);
                            await Assert.That(result.Status).IsEqualTo(allowed ? SecretStatus.Success : SecretStatus.Denied);
                            if (allowed) await Assert.That(result.Value.IsComplete && result.Value.Items.Any(t => t.Id == issued.Id("selected"))).IsTrue();
                        }
                        break;
                    case AuthTemplatePermissionAction.Attach:
                        using (var request = IdentityTemplateOperations.ListIdentityTemplates(root.Organization, IdentityTemplateAuthMethod.Kubernetes))
                        {
                            var result = await client.ExecuteAsync(request, authority, authority.IssueGrant(request.OperationId, request.Target), cancellationToken: deadline.Token);
                            await Assert.That(result.Status).IsEqualTo(allowed ? SecretStatus.Success : SecretStatus.Denied);
                            if (allowed) await Assert.That(result.Value.IsComplete && result.Value.Items.Any(t => t.Id == issued.Id("selected"))).IsTrue();
                        }
                        break;
                    case AuthTemplatePermissionAction.Create:
                        using (var fields = new IdentityTemplateKubernetesFields(IdentityTemplateTokenReviewMode.Api,
                            IdentityTemplateNullableText.FromValue("https://kubernetes.example.invalid"), caCertificate: "", verifyTlsCertificate: false, allowedAudience: "baseline"))
                            await Mutation(IdentityTemplateOperations.CreateKubernetesIdentityTemplate(root.Organization, "auth-created-" + root.Nonce, fields));
                        break;
                    case AuthTemplatePermissionAction.Edit:
                        using (var fields = new IdentityTemplateKubernetesFields(allowedAudience: "changed-" + root.Nonce))
                            await Mutation(IdentityTemplateOperations.UpdateIdentityTemplateConfiguration(root.Organization, issued.Id("selected"), fields, "auth-changed-" + root.Nonce));
                        break;
                    case AuthTemplatePermissionAction.Delete:
                        await Mutation(IdentityTemplateOperations.DeleteIdentityTemplate(root.Organization, issued.Id("selected")));
                        break;
                }
                async Task Mutation<T>(ManagementRequest<T> request) where T : notnull
                {
                    using (request)
                    {
                        var receipt = client.CreateReceipt(request);
                        var result = await client.ExecuteAsync(request, authority, authority.IssueGrant(request.OperationId, request.Target), receipt, deadline.Token);
                        await Assert.That(result.Status).IsEqualTo(allowed ? SecretStatus.Success : SecretStatus.Denied);
                        await Assert.That(receipt.Evidence).IsEqualTo(allowed ? DispatchEvidence.Applied : DispatchEvidence.Rejected);
                    }
                }
            }
        }
        async Task<AuthTemplatePermissionReceipt> Send<T>(ManagementRequest<T> request, bool setup = false) where T : notnull
        {
            using (request)
            {
                var client = env.CreateManagementClient(); var receipt = client.CreateReceipt(request);
                var role = setup ? NativeIdentityRole.Setup : boundary == "denied-authority" ? NativeIdentityRole.Denied : NativeIdentityRole.Administrative;
                var barrier = !setup && boundary == "cancellation-boundary" ? new ProjectTokenBarrier(env.Tokens(role)) : null;
                using var cancellation = CancellationTokenSource.CreateLinkedTokenSource(deadline.Token);
                using var loss = !setup && boundary == "lost-response-no-replay" ? new ProjectResponseBoundary(env.Origin, cancellation) : null;
                using var scope = loss?.Enter(); Task? entered = barrier?.Entered;
                var authority = new ManagementAuthority(client.Authority, barrier ?? env.Tokens(role), root.Organization);
                var execution = client.ExecuteAsync(request, authority, authority.IssueGrant(request.OperationId, request.Target), receipt, cancellation.Token).AsTask();
                SecretOutcome<T>? result = null; bool cancelled = false;
                try
                {
                    if (entered is not null) { await entered.WaitAsync(deadline.Token); cancellation.Cancel(); barrier!.Release(); }
                    try { result = await execution; }
                    catch (OperationCanceledException) when (cancellation.IsCancellationRequested && !deadline.IsCancellationRequested) { cancelled = true; }
                    await Assert.That(loss is null || loss.Reached).IsTrue();
                    return new(receipt, result?.Status, cancelled, request.Target.SecondaryId ?? "");
                }
                finally
                {
                    cancellation.Cancel(); barrier?.Release();
                    try { result ??= await execution; } catch (OperationCanceledException) { }
                    if (result is { IsSuccess: true } r && r.Value is IDisposable owned) owned.Dispose();
                }
            }
        }
    }
}
