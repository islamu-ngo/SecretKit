using SecretKit.Core;
using SecretKit.Infisical.Management;
using SecretKit.TestFixtures;

namespace SecretKit.Infisical.Conformance.Tests;

// Direct SDK/source calibration. Deliberately does not call Effects, Trial or
// their dispatch/read helpers; the actual response metadata is the oracle.
public sealed class InfisicalIntegrationPermissionCalibrationTests
{
    public static IEnumerable<(string Operation, string Boundary, bool Generic)> Cases() =>
        from op in IntegrationPermissionContract.Operations
        from boundary in IntegrationPermissionContract.Boundaries
        from generic in new[] { false, true }
        select (op, boundary, generic);
    [Test]
    [MethodDataSource(nameof(Cases))]
    public async Task DirectTypedListCalibratesPolicyActorsMetadataAndOriginalBoundary(string operation, string boundary, bool generic)
    {
        await using var provider = new InfisicalIntegrationPermissionFixture(); using var env = provider.Environment(operation, IntegrationPermissionAction.Read);
        var root = provider.Root(operation, IntegrationPermissionAction.Read, boundary); var plan = new IntegrationPermissionPlan(root);
        using var cap = SecretMaterial.FromText("integration-capability"); using var deadline = new CancellationTokenSource(TimeSpan.FromSeconds(25));
        var source = provider.Source.CreateClient(); using var verifier = new IntegrationPermissionVerifier(root);
        IntegrationPermissionIssued? issued = null;
        bool template = operation.Contains("ProjectTemplate", StringComparison.Ordinal), privilege = operation.Contains("IdentityPrivilegeChange", StringComparison.Ordinal),
            create = operation.Split('.').Last().StartsWith("Create", StringComparison.Ordinal), applied = boundary is not ("denied-authority" or "cancellation-boundary");
        try
        {
            await Step(IntegrationPermissionStep.Reserve, cap); await Step(IntegrationPermissionStep.Open);
            await Assert.That(issued!.Actors[0].Identity.Kind).IsEqualTo(privilege ? MemberPermissionActorKind.Machine : MemberPermissionActorKind.User);
            if (privilege) await Assert.That(issued.Actors[0].Identity.Principal).IsEqualTo(root.Authorities.Runtime);
            else await Assert.That(issued.Actors[0].Identity.Owned).IsTrue();
            await Step(IntegrationPermissionStep.Before); await Read(false); await Step(IntegrationPermissionStep.ObserveBefore);
            await Step(IntegrationPermissionStep.Arm);
            ProjectRolePermission[] permissions = [new(ProjectRoleSubject.Integrations, ProjectRoleAction.Read)];
            IntegrationPermissionReceipt original;
            if (template)
            {
                var config = new ProjectTemplateConfiguration([new(plan.Slug, plan.Slug, [new(ProjectRoleSubject.Integrations, ProjectRoleAction.Read)])],
                    ProjectTemplateCollection<ProjectTemplateEnvironment>.FromValues([new("Development", "dev", 1.5)]),
                    users: ProjectTemplateCollection<ProjectTemplateUser>.FromValues([new(plan.Username(0), [plan.Slug])]));
                original = await Send(create ? ProjectTemplateOperations.CreateProjectTemplate(root.Organization, plan.Slug, configuration: config) :
                    ProjectTemplateOperations.UpdateProjectTemplate(root.Organization, issued.Id(plan.PolicyKey), configuration: config));
            }
            else if (privilege)
            {
                var selector = new LegacyPrivilegeSelection(root.Organization, issued.Id(IntegrationPermissionPlan.Project),
                    plan.ProjectSlug, issued.Actors[0].Identity.Principal, issued.Id("member-0"));
                var change = new ProjectPrivilegeChange(permissions, PrivilegeLifetime.Permanent(), plan.Slug);
                original = await Send(create ? IdentityPrivilegeChangeOperations.CreateProjectPrivilege(selector, change) :
                    IdentityPrivilegeChangeOperations.UpdateProjectPrivilege(selector, issued.Id(plan.PolicyKey), change));
            }
            else
            {
                var change = new ProjectRoleChange(plan.Slug, plan.Slug, permissions: permissions);
                original = await Send(create ? RoleChangeOperations.CreateProjectRole(root.Organization, issued.Id(IntegrationPermissionPlan.Project), change) :
                    RoleChangeOperations.UpdateProjectRole(root.Organization, issued.Id(IntegrationPermissionPlan.Project), issued.Id(plan.PolicyKey), change));
            }
            await Step(IntegrationPermissionStep.Settle);
            var originals = verifier.Requests.Where(r => r.Phase == "original").ToArray();
            await Assert.That(originals.Length).IsEqualTo(boundary == "cancellation-boundary" ? 0 : 1);
            var commits = verifier.PolicyChanges.Where(c => c.Request != "bootstrap").ToArray();
            await Assert.That(commits.Length).IsEqualTo(applied ? 1 : 0);
            if (applied)
            {
                await Assert.That(commits[0].After!.Subject).IsEqualTo("integrations");
                await Assert.That(commits[0].After!.Actions.SequenceEqual(["read"])).IsTrue();
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
                issued.Id(IntegrationPermissionPlan.Project), issued.Id("member-0"), [new(plan.Slug)]), true);
            await Step(IntegrationPermissionStep.After); await Read(true); await Step(IntegrationPermissionStep.ObserveAfter);
            await Assert.That(verifier.Collections.Length).IsEqualTo(10);
            await Assert.That(original.Native.Evidence).IsEqualTo(evidence);
            await Assert.That(provider.Originals).IsEqualTo(boundary == "cancellation-boundary" ? 0 : 1);
            if (generic)
                await Assert.That(InfisicalGovernanceFamilies.Bindings[InfisicalIntegrationPermissionGateTests.Execute].Variants.Contains("factory." + operation)).IsTrue();
        }
        finally
        {
            try { await Step(IntegrationPermissionStep.Close); }
            finally { issued?.Erase(); }
        }
        await InfisicalIntegrationPermissionEffectTests.Clean(provider);
        async Task Step(IntegrationPermissionStep step, SecretMaterial? capability = null)
        {
            var packet = await source.StepAsync(root, step, capability, deadline.Token);
            if (step == IntegrationPermissionStep.Open) issued = new([], packet.Actors);
            verifier.Check(packet, step);
            if (issued is not null) issued = issued with { Bindings = verifier.Bindings };
        }
        async Task Read(bool after)
        {
            string selectedProject = after && applied && template ? IntegrationPermissionPlan.CopyProject : IntegrationPermissionPlan.Project;
            foreach (var (projectKey, actorIndex, selected) in new[] { (selectedProject, 0, true), (IntegrationPermissionPlan.OtherProject, 0, false),
                (selectedProject, 1, false), (selectedProject, 2, false), (selectedProject, 1, false) })
            {
                var actor = issued!.Actors[actorIndex];
                using var tokens = actor.Identity.Owned ? new MemberPermissionTokens(actor.Credential) :
                    new MemberPermissionTokens(env.Tokens(actor.Identity.Principal == root.Authorities.Runtime ? NativeIdentityRole.Runtime : NativeIdentityRole.Denied));
                var client = env.CreateManagementClient();
                using var request = ProjectConnectionOperations.ListIntegrations(root.Organization, issued.Id(projectKey));
                var authority = new ManagementAuthority(client.Authority, tokens, root.Organization, issued.Id(projectKey));
                var result = await client.ExecuteAsync(request, authority, authority.IssueGrant(request.OperationId, request.Target), cancellationToken: deadline.Token);
                bool allowed = after && applied && selected;
                await Assert.That(result.Status).IsEqualTo(allowed ? SecretStatus.Success : SecretStatus.Denied);
                if (!allowed) continue;
                await Assert.That(result.Value.IsComplete && result.Value.Items.Count == 2).IsTrue();
                for (int i = 0; i < 2; i++)
                {
                    var row = result.Value.Items[i];
                    await Assert.That(row.Id).IsEqualTo(issued.Id(projectKey + "-row-" + i));
                    await Assert.That(row.AuthorizationId).IsEqualTo(issued.Id(projectKey + "-authorization"));
                    await Assert.That(row.EnvironmentId == issued.Id(projectKey + "-env") && row.Environment.Id == row.EnvironmentId &&
                        row.Environment.Name == "Development" && row.Environment.Slug == "dev").IsTrue();
                    await Assert.That(row.Integration == "controlled-metadata-" + i && row.IsActive == (i == 0) &&
                        row.CreatedAt == "2026-01-01T00:00:00Z" && row.UpdatedAt == "2026-01-01T00:00:01Z").IsTrue();
                    await Assert.That(row.Url == (i == 0 ? "https://metadata.invalid/" + root.Nonce : null) &&
                        row.App == (i == 0 ? "app-" + root.Nonce : null) && row.AppId == (i == 0 ? "app-id" : null) &&
                        row.TargetEnvironment == (i == 0 ? "preview" : null) && row.TargetEnvironmentId == (i == 0 ? "target-env" : null) &&
                        row.TargetService == (i == 0 ? "service" : null) && row.TargetServiceId == (i == 0 ? "service-id" : null) &&
                        row.Owner == (i == 0 ? "owner" : null) && row.Path == (i == 0 ? "/metadata" : null) &&
                        row.Region == (i == 0 ? "region" : null) && row.Scope == (i == 0 ? "scope" : null) &&
                        row.SecretPath == (i == 0 ? "/secrets" : null) && row.LastUsed == (i == 0 ? "2026-01-01T00:00:02Z" : null) &&
                        row.LastSyncJobId == (i == 0 ? "unqualified-job" : null) && row.IsSynced == (i == 0 ? false : (bool?)null)).IsTrue();
                    await Assert.That(!row.HasProjectScopeAttestation && !row.HasOrganizationScopeAttestation &&
                        !row.IncludesMetadata && !row.IncludesSyncMessage).IsTrue();
                }
            }
        }
        async Task<IntegrationPermissionReceipt> Send<T>(ManagementRequest<T> request, bool setup = false) where T : notnull
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
