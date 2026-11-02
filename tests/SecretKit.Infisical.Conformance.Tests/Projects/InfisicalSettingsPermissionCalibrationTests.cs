using SecretKit.Core;
using SecretKit.Infisical.Management;
using SecretKit.TestFixtures;

namespace SecretKit.Infisical.Conformance.Tests;

// Direct SDK/source calibration. Deliberately does not call Effects, Trial or
// their dispatch helpers; typed observer reads corroborate persisted changes.
public sealed class InfisicalSettingsPermissionCalibrationTests
{
    public static IEnumerable<(string Operation, string Boundary, bool Generic)> Cases() =>
        from op in SettingsPermissionContract.SupportedOperations
        from boundary in SettingsPermissionContract.Boundaries
        from generic in new[] { false, true }
        select (op, boundary, generic);
    [Test]
    [MethodDataSource(nameof(Cases))]
    public async Task DirectTypedPatchCalibratesPolicyActorsConfigurationAndOriginalBoundary(string operation, string boundary, bool generic)
    {
        await using var provider = new InfisicalSettingsPermissionFixture(); using var env = provider.Environment(operation, SettingsPermissionAction.Edit);
        var root = provider.Root(operation, SettingsPermissionAction.Edit, boundary); var plan = new SettingsPermissionPlan(root);
        using var cap = SecretMaterial.FromText("settings-capability"); using var deadline = new CancellationTokenSource(TimeSpan.FromSeconds(25));
        var source = provider.Source.CreateClient(); using var verifier = new SettingsPermissionVerifier(root);
        SettingsPermissionIssued? issued = null;
        bool template = operation.Contains("ProjectTemplate", StringComparison.Ordinal), privilege = operation.Contains("IdentityPrivilegeChange", StringComparison.Ordinal),
            create = operation.Split('.').Last().StartsWith("Create", StringComparison.Ordinal), applied = boundary is not ("denied-authority" or "cancellation-boundary");
        try
        {
            await Step(SettingsPermissionStep.Reserve, cap); await Step(SettingsPermissionStep.Open);
            await Assert.That(issued!.Actors[0].Identity.Kind).IsEqualTo(privilege ? MemberPermissionActorKind.Machine : MemberPermissionActorKind.User);
            await Assert.That(issued.Actors.Length == 4 && issued.Actors.Select(a => a.Identity.Principal).Distinct().Count() == 4 &&
                issued.Actors.Select(a => a.Identity.Id).Distinct().Count() == 4 && issued.Actors.Select(a => a.Identity.Hash).Distinct().Count() == 4).IsTrue();
            await Assert.That(issued.Actors[0].Identity.Owned).IsTrue();
            await Assert.That(root.Authorities.All.Contains(issued.Actors[0].Identity.Principal)).IsFalse();
            await Step(SettingsPermissionStep.Before); await Read(false); await Step(SettingsPermissionStep.ObserveBefore);
            await Step(SettingsPermissionStep.Arm);
            ProjectRolePermission[] permissions = [new(ProjectRoleSubject.Settings, ProjectRoleAction.Edit)];
            SettingsPermissionReceipt original;
            if (template)
            {
                var config = new ProjectTemplateConfiguration([new(plan.Slug, plan.Slug, [new(ProjectRoleSubject.Settings, ProjectRoleAction.Edit)])],
                    ProjectTemplateCollection<ProjectTemplateEnvironment>.FromValues([new("Development", "dev", 1.5)]),
                    users: ProjectTemplateCollection<ProjectTemplateUser>.FromValues([new(plan.Username(0), [plan.Slug])]));
                original = await Send(create ? ProjectTemplateOperations.CreateProjectTemplate(root.Organization, plan.Slug, configuration: config) :
                    ProjectTemplateOperations.UpdateProjectTemplate(root.Organization, issued.Id(plan.PolicyKey), configuration: config));
            }
            else if (privilege)
            {
                var selector = new LegacyPrivilegeSelection(root.Organization, issued.Id(SettingsPermissionPlan.Project),
                    plan.ProjectSlug, issued.Actors[0].Identity.Principal, issued.Id("member-0"));
                var change = new ProjectPrivilegeChange(permissions, PrivilegeLifetime.Permanent(), plan.Slug);
                original = await Send(create ? IdentityPrivilegeChangeOperations.CreateProjectPrivilege(selector, change) :
                    IdentityPrivilegeChangeOperations.UpdateProjectPrivilege(selector, issued.Id(plan.PolicyKey), change));
            }
            else
            {
                var change = new ProjectRoleChange(plan.Slug, plan.Slug, permissions: permissions);
                original = await Send(create ? RoleChangeOperations.CreateProjectRole(root.Organization, issued.Id(SettingsPermissionPlan.Project), change) :
                    RoleChangeOperations.UpdateProjectRole(root.Organization, issued.Id(SettingsPermissionPlan.Project), issued.Id(plan.PolicyKey), change));
            }
            await Step(SettingsPermissionStep.Settle);
            var originals = verifier.Requests.Where(r => r.Phase == "original").ToArray();
            await Assert.That(originals.Length).IsEqualTo(boundary == "cancellation-boundary" ? 0 : 1);
            var commits = verifier.PolicyChanges.Where(c => c.Request != "bootstrap").ToArray();
            await Assert.That(commits.Length).IsEqualTo(applied ? 1 : 0);
            if (applied)
            {
                await Assert.That(commits[0].After!.Subject).IsEqualTo("settings");
                await Assert.That(commits[0].After!.Actions.SequenceEqual(["edit"])).IsTrue();
                await Assert.That(commits[0].After!.Configuration).IsEqualTo(originals.Single().BodyHash);
            }
            var evidence = boundary switch
            {
                "cancellation-boundary" => DispatchEvidence.NotDispatched,
                "denied-authority" => DispatchEvidence.Rejected,
                "lost-response-no-replay" => DispatchEvidence.PossiblyDispatched,
                _ => DispatchEvidence.Applied
            };
            await Assert.That(original.Native.Evidence).IsEqualTo(evidence);
            if (applied && template) _ = await Send(ProjectOperations.CreateProject(root.Organization, plan.CopySlug, plan.CopySlug, template: plan.Slug, createDefaultEnvironments: false), true);
            else if (applied && create && !privilege) _ = await Send(ProjectMembershipOperations.UpdateProjectMembershipRoles(root.Organization,
                issued.Id(SettingsPermissionPlan.Project), issued.Id("member-0"), [new(plan.Slug)]), true);
            await Step(SettingsPermissionStep.After); await Read(true); await Step(SettingsPermissionStep.ObserveAfter);
            await Assert.That(verifier.Changes.Count(c => c.DecisionHash.Length > 0)).IsEqualTo(10);
            await Assert.That(original.Native.Evidence).IsEqualTo(evidence);
            await Assert.That(provider.Originals).IsEqualTo(boundary == "cancellation-boundary" ? 0 : 1);
            if (generic)
                await Assert.That(InfisicalGovernanceFamilies.Bindings[InfisicalSettingsPermissionGateTests.Execute].Variants.Contains("factory." + operation)).IsTrue();
        }
        finally
        {
            try { await Step(SettingsPermissionStep.Close); }
            finally { issued?.Erase(); }
        }
        await InfisicalSettingsPermissionEffectTests.Clean(provider);
        async Task Step(SettingsPermissionStep step, SecretMaterial? capability = null)
        {
            var packet = await source.StepAsync(root, step, capability, deadline.Token);
            if (step == SettingsPermissionStep.Open) issued = new([], packet.Actors);
            verifier.Check(packet, step);
            if (issued is not null) issued = issued with { Bindings = verifier.Bindings };
        }
        async Task Read(bool after)
        {
            string selectedProject = after && applied && template ? SettingsPermissionPlan.CopyProject : SettingsPermissionPlan.Project;
            foreach (var (projectKey, actorIndex, selected) in new[] { (selectedProject, 0, true), (SettingsPermissionPlan.OtherProject, 0, false),
                (selectedProject, 1, false), (selectedProject, 2, false), (selectedProject, 3, false) })
            {
                var actor = issued!.Actors[actorIndex];
                using var tokens = actor.Identity.Owned ? new MemberPermissionTokens(actor.Credential) :
                    new MemberPermissionTokens(env.Tokens(actor.Identity.Principal == root.Authorities.Runtime ? NativeIdentityRole.Runtime : NativeIdentityRole.Denied));
                var client = env.CreateManagementClient();
                using var request = ProjectOperations.UpdateProject(root.Organization, issued.Id(projectKey),
                    "changed-" + root.Nonce, "changed-" + root.Nonce, "changed description " + root.Nonce);
                var receipt = client.CreateReceipt(request);
                var authority = new ManagementAuthority(client.Authority, tokens, root.Organization, issued.Id(projectKey));
                var result = await client.ExecuteAsync(request, authority, authority.IssueGrant(request.OperationId, request.Target), receipt, deadline.Token);
                bool allowed = after && applied && selected;
                await Assert.That(result.Status).IsEqualTo(allowed ? SecretStatus.Success : SecretStatus.Denied);
                await Assert.That(receipt.Evidence).IsEqualTo(allowed ? DispatchEvidence.Applied : DispatchEvidence.Rejected);
                if (allowed)
                {
                    await Assert.That(result.Value.Name == "changed-" + root.Nonce && result.Value.Slug == "changed-" + root.Nonce &&
                        result.Value.Description == "changed description " + root.Nonce && result.Value.Type == "secret-manager").IsTrue();
                }
                using var readback = ProjectOperations.GetProject(root.Organization, issued.Id(projectKey));
                var observer = new ManagementAuthority(client.Authority, env.Tokens(NativeIdentityRole.Observer), root.Organization, issued.Id(projectKey));
                var stored = await client.ExecuteAsync(readback, observer, observer.IssueGrant(readback.OperationId, readback.Target), cancellationToken: deadline.Token);
                bool changed = after && applied && projectKey == selectedProject;
                string baseline = projectKey == SettingsPermissionPlan.CopyProject ? plan.CopySlug : projectKey == SettingsPermissionPlan.Project ? plan.ProjectSlug : "other-" + plan.ProjectSlug;
                await Assert.That(stored.IsSuccess && stored.Value.Name == (changed ? "changed-" + root.Nonce : baseline) &&
                    stored.Value.Slug == (changed ? "changed-" + root.Nonce : baseline) && stored.Value.Description == (changed ? "changed description " + root.Nonce : "baseline " + root.Nonce) &&
                    !stored.Value.HasDeleteProtection.Value && !stored.Value.SecretSharing.Value && stored.Value.Version.Value == 3).IsTrue();
            }
        }
        async Task<SettingsPermissionReceipt> Send<T>(ManagementRequest<T> request, bool setup = false) where T : notnull
        {
            using (request)
            {
                var client = env.CreateManagementClient(); var receipt = client.CreateReceipt(request);
                var role = setup ? NativeIdentityRole.Setup : boundary == "denied-authority" ? NativeIdentityRole.Denied : NativeIdentityRole.Administrative;
                var barrier = !setup && boundary == "cancellation-boundary" ? new ProjectTokenBarrier(env.Tokens(role)) : null;
                using var cancel = CancellationTokenSource.CreateLinkedTokenSource(deadline.Token);
                using var loss = !setup && boundary == "lost-response-no-replay" ? new ProjectResponseBoundary(env.Origin, cancel) : null;
                using var scope = loss?.Enter(); Task? entered = barrier?.Entered;
                var authority = new ManagementAuthority(client.Authority, barrier ?? env.Tokens(role), root.Organization, request.Target.ProjectId);
                var execution = client.ExecuteAsync(request, authority, authority.IssueGrant(request.OperationId, request.Target), receipt, cancel.Token).AsTask();
                SecretOutcome<T>? result = null; bool cancelled = false;
                try
                {
                    if (entered is not null) { await entered.WaitAsync(deadline.Token); cancel.Cancel(); barrier!.Release(); }
                    try { result = await execution; } catch (OperationCanceledException) when (cancel.IsCancellationRequested && !deadline.IsCancellationRequested) { cancelled = true; }
                    await Assert.That(loss is null || loss.Reached).IsTrue();
                    return new(receipt, result?.Status, cancelled, request.Target.SecondaryId ?? "");
                }
                finally
                {
                    cancel.Cancel(); barrier?.Release(); try { result ??= await execution; } catch (OperationCanceledException) { }
                    if (result is { IsSuccess: true } r && r.Value is IDisposable disposable) disposable.Dispose();
                }
            }
        }
    }
}
