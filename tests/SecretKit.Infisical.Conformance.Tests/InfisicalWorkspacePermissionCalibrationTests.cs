using SecretKit.Core;
using SecretKit.Infisical.Management;
using SecretKit.TestFixtures;

namespace SecretKit.Infisical.Conformance.Tests;

// Supported paths calibrate the SDK/source directly. Retained gated variants
// must fail before enrollment rather than calibrate an unrelated settings API.
public sealed class InfisicalWorkspacePermissionCalibrationTests
{
    public static IEnumerable<(string Operation, string Variant, string Boundary)> Cases() => InfisicalWorkspacePermissionOriginalTests.Cases();
    [Test]
    [MethodDataSource(nameof(Cases))]
    public Task DirectSdkCalibratesPersistedWorkspacePolicyAndTerminalLifecycle(string operation, string variant, string boundary) => Calibrate(operation, variant, boundary);
    public static IEnumerable<(string Operation, string Boundary, int Action)> GenericCases() => InfisicalWorkspacePermissionOriginalTests.GenericCases();
    [Test]
    [MethodDataSource(nameof(GenericCases))]
    public async Task IndependentGenericCalibrationRetainsOriginalFactory(string operation, string boundary, int action)
    {
        await Assert.That(InfisicalGovernanceFamilies.Bindings[InfisicalWorkspacePermissionGateTests.Execute].Variants.Contains("factory." + operation)).IsTrue();
        await Calibrate(operation, WorkspacePermissionContract.Variant((WorkspacePermissionAction)action), boundary);
    }
    private static async Task Calibrate(string operation, string variant, string boundary)
    {
        var action = InfisicalWorkspacePermissionGateTests.Action(variant);
        await using var provider = new InfisicalWorkspacePermissionFixture(); using var env = provider.Environment(operation, action);
        if (WorkspacePermissionContract.Gate(WorkspacePermissionContract.Scope(operation), action) is not null)
        {
            var rejected = await InfisicalWorkspacePermissionEffectTests.RunAsync(provider, operation, variant, boundary);
            await Assert.That(rejected.Passed).IsFalse();
            await Assert.That(provider.Opens).IsEqualTo(0);
            await InfisicalWorkspacePermissionEffectTests.Clean(provider);
            return;
        }
        using var deadline = new CancellationTokenSource(TimeSpan.FromSeconds(45)); using var cap = SecretMaterial.FromText("workspace-capability");
        var root = provider.Root(operation, action, boundary); var plan = new WorkspacePermissionPlan(root); var source = provider.Source.CreateClient();
        using var verifier = new WorkspacePermissionVerifier(root); var ownership = new WorkspacePermissionOwnership(root, plan);
        WorkspacePermissionIssued? issued = null;
        bool org = operation.EndsWith("OrganizationRole", StringComparison.Ordinal), template = operation.Contains("ProjectTemplate", StringComparison.Ordinal),
            privilege = operation.Contains("IdentityPrivilegeChange", StringComparison.Ordinal), create = operation.Split('.').Last().StartsWith("Create", StringComparison.Ordinal),
            applied = boundary is not ("denied-authority" or "cancellation-boundary");
        var expected = new Dictionary<string, WorkspacePermissionState>();
        try
        {
            Check(await source.StepAsync(root, WorkspacePermissionStep.Reserve, cap, deadline.Token), WorkspacePermissionStep.Reserve);
            await Assert.That(provider.Generated).IsEqualTo(0);
            var opened = await source.StepAsync(root, WorkspacePermissionStep.Open, null, deadline.Token);
            issued = new(opened.Owner.Payload.Content.Actors, opened.Storage.Payload.Content.Bindings); Check(opened, WorkspacePermissionStep.Open);
            foreach (var row in plan.Rows.Where(r => r.Window != "copy" && r.Action != WorkspacePermissionAction.Create).DistinctBy(r => r.Target)) expected.Add(row.Target, Initial(row));
            await Witness(false);
            Check(await source.StepAsync(root, WorkspacePermissionStep.Arm, null, deadline.Token), WorkspacePermissionStep.Arm);
            WorkspacePermissionReceipt original;
            if (org)
            {
                var change = new OrganizationRoleChange(plan.Slug, plan.Slug,
                    permissions: [new(OrganizationRoleSubject.Workspace, Enum.Parse<OrganizationRoleAction>(action.ToString()))]);
                original = await Original(create ? RoleChangeOperations.CreateOrganizationRole(root.Organization, change) :
                    RoleChangeOperations.UpdateOrganizationRole(root.Organization, issued.Id(plan.PolicyKey), change));
            }
            else
            {
                var selected = Enum.Parse<ProjectRoleAction>(action.ToString());
                if (template)
                {
                    var config = new ProjectTemplateConfiguration(
                        [new(plan.Slug, plan.Slug, [new(ProjectRoleSubject.Workspace, selected)])],
                        ProjectTemplateCollection<ProjectTemplateEnvironment>.FromValues([]),
                        users: ProjectTemplateCollection<ProjectTemplateUser>.FromValues([new(plan.Username(plan.ActorKey(0)), [plan.Slug])]),
                        groups: ProjectTemplateCollection<ProjectTemplateGroup>.FromValues([]),
                        identities: ProjectTemplateCollection<ProjectTemplateIdentity>.FromValues([]),
                        projectManagedIdentities: ProjectTemplateCollection<ProjectTemplateManagedIdentity>.FromValues([]));
                    original = await Original(create ? ProjectTemplateOperations.CreateProjectTemplate(root.Organization, plan.Slug, configuration: config) :
                        ProjectTemplateOperations.UpdateProjectTemplate(root.Organization, issued.Id(plan.PolicyKey), configuration: config));
                }
                else
                {
                    ProjectRolePermission[] permissions = [new(ProjectRoleSubject.Workspace, selected)];
                    if (privilege)
                    {
                        await Assert.That(issued.Actors[0].Principal).IsEqualTo(InfisicalWorkspacePermissionFixture.Authorities.Runtime);
                        await Assert.That(issued.Actors[0].Kind).IsEqualTo(MemberPermissionActorKind.Machine);
                        var selection = new LegacyPrivilegeSelection(root.Organization, issued.Id(WorkspacePermissionPlan.Project), plan.ProjectSlug,
                            issued.Actors[0].Principal, issued.Id(plan.ActorMembership(0)));
                        var change = new ProjectPrivilegeChange(permissions, PrivilegeLifetime.Permanent(), plan.Slug);
                        original = await Original(create ? IdentityPrivilegeChangeOperations.CreateProjectPrivilege(selection, change) :
                            IdentityPrivilegeChangeOperations.UpdateProjectPrivilege(selection, issued.Id(plan.PolicyKey), change));
                    }
                    else
                    {
                        var change = new ProjectRoleChange(plan.Slug, plan.Slug, permissions: permissions);
                        original = await Original(create ? RoleChangeOperations.CreateProjectRole(root.Organization, issued.Id(WorkspacePermissionPlan.Project), change) :
                            RoleChangeOperations.UpdateProjectRole(root.Organization, issued.Id(WorkspacePermissionPlan.Project), issued.Id(plan.PolicyKey), change));
                    }
                }
            }
            var settled = await source.StepAsync(root, WorkspacePermissionStep.Settle, null, deadline.Token); Check(settled, WorkspacePermissionStep.Settle);
            await Assert.That(settled.Ingress.Payload.Content.Length).IsEqualTo(boundary == "cancellation-boundary" ? 0 : 1);
            await Assert.That(settled.Policy.Payload.Content.Commits.Length).IsEqualTo(applied ? 1 : 0);
            if (applied)
            {
                var persisted = settled.Policy.Payload.Content.Commits.Single();
                await Assert.That(persisted.Request).IsEqualTo(settled.Ingress.Payload.Content.Single().Request);
                await Assert.That(persisted.Policy.Actor).IsEqualTo(issued.Actors[0].Principal);
                await Assert.That(persisted.Policy.Kind).IsEqualTo(privilege ? MemberPermissionActorKind.Machine : MemberPermissionActorKind.User);
                await Assert.That(persisted.Policy.Subject).IsEqualTo("workspace");
                await Assert.That(persisted.Policy.Actions.SequenceEqual([WorkspacePermissionContract.Wire(action)])).IsTrue();
                await Assert.That(persisted.Policy.Names.Length).IsEqualTo(0); await Assert.That(persisted.Policy.Role).IsEqualTo(plan.Slug);
                await Assert.That(persisted.Policy.Resource).IsEqualTo(issued.Id(plan.PolicyKey));
                await Assert.That(persisted.Policy.Organization).IsEqualTo(root.Organization);
                await Assert.That(persisted.Policy.Project).IsEqualTo(org || template ? "" : issued.Id(WorkspacePermissionPlan.Project));
                if (template) await Assert.That(persisted.Policy.TemplateConfiguration).IsEqualTo(plan.TemplateConfiguration());
            }
            await Assert.That(original.Native.Evidence).IsEqualTo(boundary switch
            {
                "denied-authority" => DispatchEvidence.Rejected,
                "cancellation-boundary" => DispatchEvidence.NotDispatched,
                "lost-response-no-replay" => DispatchEvidence.PossiblyDispatched,
                _ => DispatchEvidence.Applied
            });
            if (applied && template) _ = await Original(ProjectOperations.CreateProject(root.Organization, plan.CopySlug, plan.CopySlug,
                template: plan.Slug, createDefaultEnvironments: false), true);
            else if (applied && create && !privilege)
            {
                if (org) _ = await Original(OrganizationMembershipOperations.UpdateOrganizationMembership(root.Organization, issued.Id(plan.ActorMembership(0)), role: plan.Slug), true);
                else _ = await Original(ProjectMembershipOperations.UpdateProjectMembershipRoles(root.Organization, issued.Id(WorkspacePermissionPlan.Project),
                    issued.Id(plan.ActorMembership(0)), [new(plan.Slug)]), true);
            }
            var retainedEvidence = original.Native.Evidence; await Witness(true);
            await Assert.That(original.Native.Evidence).IsEqualTo(retainedEvidence);
            await Assert.That(provider.Originals).IsEqualTo(boundary == "cancellation-boundary" ? 0 : 1);
        }
        finally
        {
            try { Check(await source.StepAsync(root, WorkspacePermissionStep.Close, null, CancellationToken.None), WorkspacePermissionStep.Close); }
            finally { issued?.Erase(); }
        }
        await InfisicalWorkspacePermissionEffectTests.Clean(provider);
        void Check(WorkspacePermissionPacket packet, WorkspacePermissionStep step)
        {
            verifier.Check(packet, step); ownership.Check(packet, step);
            if (issued is not null) issued = issued with { Bindings = packet.Storage.Payload.Content.Bindings };
        }
        async Task<WorkspacePermissionReceipt> Original<T>(ManagementRequest<T> request, bool setup = false) where T : notnull
        {
            using (request)
            {
                var client = env.CreateManagementClient(); var receipt = client.CreateReceipt(request);
                var identity = setup ? NativeIdentityRole.Setup : boundary == "denied-authority" ? NativeIdentityRole.Denied : NativeIdentityRole.Administrative;
                var barrier = !setup && boundary == "cancellation-boundary" ? new ProjectTokenBarrier(env.Tokens(identity)) : null;
                using var cancellation = CancellationTokenSource.CreateLinkedTokenSource(deadline.Token);
                using var loss = !setup && boundary == "lost-response-no-replay" ? new ProjectResponseBoundary(env.Origin, cancellation) : null;
                using var scope = loss?.Enter(); Task? signal = barrier?.Entered;
                var authority = new ManagementAuthority(client.Authority, barrier ?? env.Tokens(identity), root.Organization, request.Target.ProjectId);
                var execution = client.ExecuteAsync(request, authority, authority.IssueGrant(request.OperationId, request.Target), receipt, cancellation.Token).AsTask();
                SecretOutcome<T>? result = null; bool cancelled = false;
                try
                {
                    if (signal is not null) { await signal.WaitAsync(deadline.Token); cancellation.Cancel(); barrier!.Release(); }
                    try { result = await execution; }
                    catch (OperationCanceledException) when (cancellation.IsCancellationRequested && !deadline.IsCancellationRequested) { cancelled = true; }
                    await Assert.That(loss is null || loss.Reached).IsTrue();
                    if (setup) await Assert.That(result is { IsSuccess: true }).IsTrue();
                    return new(receipt, result?.Status, cancelled, request.Target.SecondaryId ?? "");
                }
                finally
                {
                    cancellation.Cancel(); barrier?.Release();
                    try { result ??= await execution; } catch (OperationCanceledException) { }
                    if (result is { IsSuccess: true } completed && completed.Value is IDisposable owned) owned.Dispose();
                }
            }
        }
        WorkspacePermissionState Initial(WorkspacePermissionRow row) => new(row.Target, issued!.Id(row.Target), issued.Id(row.Organization), issued.Id(row.Project), row.Name, row.Slug, "closed-v1", WorkspacePermissionPlan.Configuration(false), 1);
        async Task Witness(bool after)
        {
            var step = after ? WorkspacePermissionStep.After : WorkspacePermissionStep.Before;
            var beforePacket = await source.StepAsync(root, step, null, deadline.Token); Check(beforePacket, step);
            if (after && template && applied)
                foreach (var row in plan.Rows.Where(r => r.Window == "copy" && r.Action != WorkspacePermissionAction.Create).DistinctBy(r => r.Target)) expected.TryAdd(row.Target, Initial(row));
            var rows = plan.Rows.Where(r => r.Window == (!after ? "before" : template && applied ? "copy" : "after")).ToArray();
            var returned = new Dictionary<string, ProjectSummary>(); var submitted = new Dictionary<string, string>();
            foreach (var row in rows)
            {
                var actor = issued!.Actors[row.Actor]; string organization = issued.Id(row.Organization), target = issued.Id(row.Target);
                using var tokens = actor.Owned ? new MemberPermissionTokens(actor.Credential) : new MemberPermissionTokens(env.Tokens(
                    actor.Principal == root.Authorities.Runtime ? NativeIdentityRole.Runtime : NativeIdentityRole.Denied));
                var client = env.CreateManagementClient();
                using var request = row.Action switch
                {
                    WorkspacePermissionAction.Create => ProjectOperations.CreateProject(organization, row.Name, row.Slug, "closed-v1", deleteProtection: false, createDefaultEnvironments: false),
                    WorkspacePermissionAction.Edit => ProjectOperations.UpdateProject(organization, target, name: row.Name + "-edited", slug: row.Slug + "-v2", description: "closed-v2",
                        deleteProtection: false, auditRetentionDays: 17, secretSharing: true, autoCapitalization: true, encryptedMetadata: true, pointInTimeVersionLimit: 23,
                        showLegacySnapshots: true, secretDetectionIgnoreValues: []),
                    _ => ProjectOperations.DeleteProject(organization, target)
                };
                submitted.Add(row.Key, request.Target.SecondaryId ?? WorkspacePermissionContract.RawHash([]));
                bool allowed = after && applied && row.Control == "selected" && row.Action == action;
                var authority = new ManagementAuthority(client.Authority, tokens, organization, request.Target.ProjectId);
                var receipt = client.CreateReceipt(request);
                var result = await client.ExecuteAsync(request, authority, authority.IssueGrant(request.OperationId, request.Target), receipt, deadline.Token);
                await Assert.That(result.Status).IsEqualTo(allowed ? SecretStatus.Success : SecretStatus.Denied).Because(result.Status.ToString());
                await Assert.That(tokens.Hash).IsEqualTo(actor.CredentialHash);
                await Assert.That(receipt.Evidence).IsEqualTo(allowed ? DispatchEvidence.Applied : DispatchEvidence.Rejected);
                if (allowed) returned.Add(row.Key, result.Value);
            }
            var end = after ? WorkspacePermissionStep.ObserveAfter : WorkspacePermissionStep.ObserveBefore;
            var packet = await source.StepAsync(root, end, null, deadline.Token); Check(packet, end);
            await Assert.That(packet.Access.Payload.Content.Length).IsEqualTo(rows.Length);
            for (int index = 0; index < rows.Length; index++)
            {
                var row = rows[index]; var decision = packet.Access.Payload.Content[index]; var actor = issued!.Actors[row.Actor];
                await Assert.That(decision.Target).IsEqualTo(issued.Id(row.Target)); await Assert.That(decision.Action).IsEqualTo(row.Action);
                await Assert.That(decision.Actor).IsEqualTo(actor.Principal); await Assert.That(decision.Kind).IsEqualTo(actor.Kind);
                await Assert.That(decision.CredentialId).IsEqualTo(actor.CredentialId); await Assert.That(decision.CredentialHash).IsEqualTo(actor.CredentialHash);
                await Assert.That(decision.Organization).IsEqualTo(issued.Id(row.Organization)); await Assert.That(decision.Project).IsEqualTo(issued.Id(row.Project));
                var ingress = packet.Ingress.Payload.Content.Single(e => e.Request == decision.Request);
                await Assert.That(ingress.BodyHash).IsEqualTo(submitted[row.Key]);
                await Assert.That(ingress.Path).IsEqualTo("/api/v1/projects" + (row.Action == WorkspacePermissionAction.Create ? "" : "/" + issued.Id(row.Target)));
                await Assert.That(packet.Issuer.Payload.Content.Credentials.Any(c => c.Id == decision.CredentialId && c.Principal == decision.Actor && c.Kind == decision.Kind && c.Hash == decision.CredentialHash)).IsTrue();
                var before = expected.GetValueOrDefault(row.Target); var next = before;
                if (returned.TryGetValue(row.Key, out var value))
                {
                    bool edit = row.Action == WorkspacePermissionAction.Edit;
                    var full = Initial(row) with
                    {
                        Name = edit ? row.Name + "-edited" : row.Name,
                        Slug = edit ? row.Slug + "-v2" : row.Slug,
                        Description = edit ? "closed-v2" : "closed-v1",
                        Configuration = WorkspacePermissionPlan.Configuration(edit),
                        Version = edit ? 2 : 1
                    };
                    await Assert.That(value.Id).IsEqualTo(full.Target); await Assert.That(value.Name).IsEqualTo(full.Name); await Assert.That(value.Slug).IsEqualTo(full.Slug);
                    await Assert.That(value.Description).IsEqualTo(full.Description); await Assert.That(value.HasDeleteProtection.Value).IsFalse();
                    await Assert.That(value.AuditLogsRetentionDays.Value).IsEqualTo(edit ? 17d : 7d); await Assert.That(value.PitVersionLimit.Value).IsEqualTo(edit ? 23d : 10d);
                    await Assert.That(value.SecretSharing.Value).IsEqualTo(edit); await Assert.That(value.AutoCapitalization.Value).IsEqualTo(edit);
                    await Assert.That(value.EnforceEncryptedSecretManagerSecretMetadata.Value).IsEqualTo(edit); await Assert.That(value.ShowSnapshotsLegacy.Value).IsEqualTo(edit);
                    await Assert.That(value.SecretDetectionIgnoreValues.Value.Count).IsEqualTo(0);
                    next = row.Action == WorkspacePermissionAction.Delete ? null : full;
                    if (next is null)
                    {
                        await Assert.That(index).IsEqualTo(rows.Length - 1);
                        var grant = beforePacket.Policy.Payload.Content.Inventory.Single(p => p.Project == decision.Project && p.Actor == actor.Principal);
                        var membership = beforePacket.Membership.Payload.Content.Single(j => j.Project == decision.Project && j.Principal == actor.Principal);
                        await Assert.That(membership.Active && membership.Assigned && membership.Status == "accepted").IsTrue();
                        await Assert.That(membership.RoleId).IsEqualTo(grant.Resource);
                        var removed = beforePacket.Owner.Payload.Content.Remaining.Where(r => r.CanonicalId == decision.Project || issued.Bindings.Any(b => b.CanonicalId == r.CanonicalId && b.Scope == decision.Project)).OrderBy(r => r.Intent).ToArray();
                        var preserved = beforePacket.Owner.Payload.Content.Remaining.Except(removed).OrderBy(r => r.Intent).ToArray();
                        var cascade = packet.Storage.Payload.Content.Cascades.Single();
                        await Assert.That(cascade.Request).IsEqualTo(decision.Request); await Assert.That(cascade.Project).IsEqualTo(decision.Project);
                        await Assert.That(cascade.PolicyHash).IsEqualTo(WorkspacePermissionContract.Hash(grant)); await Assert.That(cascade.MembershipHash).IsEqualTo(WorkspacePermissionContract.Hash(membership));
                        await Assert.That(cascade.Removed.OrderBy(r => r.Intent).SequenceEqual(removed)).IsTrue();
                        await Assert.That(cascade.Retained.OrderBy(r => r.Intent).SequenceEqual(preserved)).IsTrue();
                        await Assert.That(packet.Owner.Payload.Content.Remaining.OrderBy(r => r.Intent).SequenceEqual(preserved)).IsTrue();
                        await Assert.That(packet.Membership.Payload.Content.Any(j => j.Project == decision.Project)).IsFalse();
                        await Assert.That(packet.Policy.Payload.Content.Inventory.Any(p => p.Project == decision.Project)).IsFalse();
                        await Assert.That(issued.Bindings.Any(b => b.CanonicalId == decision.Project)).IsTrue();
                    }
                }
                await Assert.That(packet.Storage.Payload.Content.Changes.Single(c => c.Request == decision.Request)).IsEqualTo(new WorkspacePermissionChange(decision.Request, row.Key, before, next));
                if (next is null) expected.Remove(row.Target); else expected[row.Target] = next;
            }
            await Assert.That(packet.Storage.Payload.Content.Inventory.OrderBy(s => s.Row).SequenceEqual(expected.Values.OrderBy(s => s.Row))).IsTrue();
            var observer = env.CreateManagementClient(); using var list = ProjectOperations.ListProjects(root.Organization);
            var observerAuthority = new ManagementAuthority(observer.Authority, env.Tokens(NativeIdentityRole.Observer), root.Organization);
            var inventory = await observer.ExecuteAsync(list, observerAuthority, observerAuthority.IssueGrant(list.OperationId, list.Target), cancellationToken: deadline.Token);
            await Assert.That(inventory.IsSuccess && inventory.Value.IsComplete).IsTrue();
            await Assert.That(inventory.Value.Items.Select(p => p.Id).Order().SequenceEqual(expected.Values.Select(p => p.Target).Order())).IsTrue();
            foreach (var binding in issued!.Bindings.Where(b => b.Kind == "project"))
            {
                using var get = ProjectOperations.GetProject(root.Organization, binding.CanonicalId);
                var authority = new ManagementAuthority(observer.Authority, env.Tokens(NativeIdentityRole.Observer), root.Organization, binding.CanonicalId);
                var result = await observer.ExecuteAsync(get, authority, authority.IssueGrant(get.OperationId, get.Target), cancellationToken: deadline.Token);
                var state = expected.Values.SingleOrDefault(s => s.Target == binding.CanonicalId);
                await Assert.That(result.Status).IsEqualTo(state is null ? SecretStatus.Absent : SecretStatus.Success);
                if (state is null) continue;
                await Assert.That(result.Value.Environments.IsPresent && result.Value.Environments.Value.Count == 0 && result.Value.DeletedEnvironments.IsPresent && result.Value.DeletedEnvironments.Value.Count == 0).IsTrue();
                await Assert.That(result.Value.Name).IsEqualTo(state.Name); await Assert.That(result.Value.Slug).IsEqualTo(state.Slug);
                using var bySlug = ProjectOperations.GetProjectBySlug(root.Organization, state.Slug);
                var fetched = await observer.ExecuteAsync(bySlug, observerAuthority, observerAuthority.IssueGrant(bySlug.OperationId, bySlug.Target), cancellationToken: deadline.Token);
                await Assert.That(fetched.IsSuccess && fetched.Value.Id == state.Target).IsTrue();
            }
        }
    }
}
