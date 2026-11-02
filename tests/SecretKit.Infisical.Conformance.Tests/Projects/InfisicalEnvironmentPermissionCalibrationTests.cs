using SecretKit.Core;
using SecretKit.Infisical.Management;
using SecretKit.TestFixtures;

namespace SecretKit.Infisical.Conformance.Tests;

// Independent direct SDK/source calibration: no Effects, Client or Trial calls.
public sealed class InfisicalEnvironmentPermissionCalibrationTests
{
    public static IEnumerable<(string Operation, string Variant, string Boundary)> Cases() => InfisicalEnvironmentPermissionOriginalTests.Cases();
    [Test]
    [MethodDataSource(nameof(Cases))]
    public Task DirectSdkCalibratesPersistedEnvironmentPolicyAndDownstreamCrud(string operation, string variant, string boundary) => Calibrate(operation, variant, boundary);
    public static IEnumerable<(string Operation, string Boundary, int Action)> GenericCases() => InfisicalEnvironmentPermissionOriginalTests.GenericCases();
    [Test]
    [MethodDataSource(nameof(GenericCases))]
    public async Task IndependentGenericCalibrationRetainsOriginalFactory(string operation, string boundary, int action)
    {
        await Assert.That(InfisicalGovernanceFamilies.Bindings[InfisicalEnvironmentPermissionGateTests.Execute].Variants.Contains("factory." + operation)).IsTrue();
        await Calibrate(operation, EnvironmentPermissionContract.Variant((EnvironmentPermissionAction)action), boundary);
    }
    private static async Task Calibrate(string operation, string variant, string boundary)
    {
        var action = InfisicalEnvironmentPermissionGateTests.Action(variant);
        await using var provider = new InfisicalEnvironmentPermissionFixture(); using var env = provider.Environment(operation, action);
        using var deadline = new CancellationTokenSource(TimeSpan.FromSeconds(45)); using var cap = SecretMaterial.FromText("environment-capability");
        var root = provider.Root(operation, action, boundary); var plan = new EnvironmentPermissionPlan(root); var source = provider.Source.CreateClient();
        using var verifier = new EnvironmentPermissionVerifier(root); var ownership = new EnvironmentPermissionOwnership(root, plan);
        EnvironmentPermissionIssued? issued = null;
        bool template = operation.Contains("ProjectTemplate", StringComparison.Ordinal),
            privilege = operation.Contains("IdentityPrivilegeChange", StringComparison.Ordinal), create = operation.Split('.').Last().StartsWith("Create", StringComparison.Ordinal),
            applied = boundary is not ("denied-authority" or "cancellation-boundary");
        var expected = new Dictionary<string, EnvironmentPermissionState>();
        try
        {
            Check(await source.StepAsync(root, EnvironmentPermissionStep.Reserve, cap, deadline.Token), EnvironmentPermissionStep.Reserve);
            await Assert.That(provider.Generated).IsEqualTo(0);
            var opened = await source.StepAsync(root, EnvironmentPermissionStep.Open, null, deadline.Token);
            issued = new(opened.Owner.Payload.Content.Actors, opened.Storage.Payload.Content.Bindings); Check(opened, EnvironmentPermissionStep.Open);
            foreach (var row in plan.Rows.Where(r => r.Window != "copy" && r.Action != EnvironmentPermissionAction.Create)) expected.Add(row.Key, Initial(row));
            var deleted = plan.DeletedEnvironment;
            var tombstone = opened.Storage.Payload.Content.Inventory.Single(s => s.Row == deleted.Key);
            await Assert.That(tombstone with { Deleted = false, SoftDeletedAt = null, DeleteAfter = null, DeletedBy = null }).IsEqualTo(Initial(deleted));
            await Assert.That(tombstone.Deleted && DateTimeOffset.TryParse(tombstone.SoftDeletedAt, out _) && DateTimeOffset.TryParse(tombstone.DeleteAfter, out _) &&
                tombstone.DeletedBy == "identity:" + root.Authorities.Setup).IsTrue();
            expected.Add(deleted.Key, tombstone);
            await Witness(false);
            Check(await source.StepAsync(root, EnvironmentPermissionStep.Arm, null, deadline.Token), EnvironmentPermissionStep.Arm);
            EnvironmentPermissionReceipt original;
            var selected = Enum.Parse<ProjectRoleAction>(action.ToString());
            if (template)
            {
                var config = new ProjectTemplateConfiguration(
                    [new(plan.Slug, plan.Slug, [new(ProjectRoleSubject.Environments, selected)])],
                    ProjectTemplateCollection<ProjectTemplateEnvironment>.FromValues([new("Witness", "witness", 1.5)]),
                    users: ProjectTemplateCollection<ProjectTemplateUser>.FromValues([new(plan.Username(plan.ActorKey(0)), [plan.Slug])]));
                original = await Original(create ? ProjectTemplateOperations.CreateProjectTemplate(root.Organization, plan.Slug, configuration: config) :
                    ProjectTemplateOperations.UpdateProjectTemplate(root.Organization, issued.Id(plan.PolicyKey), configuration: config));
            }
            else
            {
                ProjectRolePermission[] permissions = [new(ProjectRoleSubject.Environments, selected)];
                if (privilege)
                {
                    await Assert.That(issued.Actors[0].Principal).IsEqualTo(InfisicalEnvironmentPermissionFixture.Authorities.Runtime);
                    await Assert.That(issued.Actors[0].Kind).IsEqualTo(MemberPermissionActorKind.Machine);
                    var selection = new LegacyPrivilegeSelection(root.Organization, issued.Id(EnvironmentPermissionPlan.Project), plan.ProjectSlug,
                        issued.Actors[0].Principal, issued.Id(plan.ActorMembership(0)));
                    var change = new ProjectPrivilegeChange(permissions, PrivilegeLifetime.Permanent(), plan.Slug);
                    original = await Original(create ? IdentityPrivilegeChangeOperations.CreateProjectPrivilege(selection, change) :
                        IdentityPrivilegeChangeOperations.UpdateProjectPrivilege(selection, issued.Id(plan.PolicyKey), change));
                }
                else
                {
                    var change = new ProjectRoleChange(plan.Slug, plan.Slug, permissions: permissions);
                    original = await Original(create ? RoleChangeOperations.CreateProjectRole(root.Organization, issued.Id(EnvironmentPermissionPlan.Project), change) :
                        RoleChangeOperations.UpdateProjectRole(root.Organization, issued.Id(EnvironmentPermissionPlan.Project), issued.Id(plan.PolicyKey), change));
                }
            }
            var settled = await source.StepAsync(root, EnvironmentPermissionStep.Settle, null, deadline.Token); Check(settled, EnvironmentPermissionStep.Settle);
            await Assert.That(settled.Ingress.Payload.Content.Length).IsEqualTo(boundary == "cancellation-boundary" ? 0 : 1);
            await Assert.That(settled.Policy.Payload.Content.Commits.Length).IsEqualTo(applied ? 1 : 0);
            if (applied)
            {
                var persisted = settled.Policy.Payload.Content.Commits.Single();
                await Assert.That(persisted.Request).IsEqualTo(settled.Ingress.Payload.Content.Single().Request);
                await Assert.That(persisted.Policy.Actor).IsEqualTo(issued.Actors[0].Principal);
                await Assert.That(persisted.Policy.Kind).IsEqualTo(privilege ? MemberPermissionActorKind.Machine : MemberPermissionActorKind.User);
                await Assert.That(persisted.Policy.Subject).IsEqualTo("environments");
                await Assert.That(persisted.Policy.Actions.SequenceEqual([EnvironmentPermissionContract.Wire(action)])).IsTrue();
                await Assert.That(persisted.Policy.Names.Length).IsEqualTo(0); await Assert.That(persisted.Policy.Role).IsEqualTo(plan.Slug);
                await Assert.That(persisted.Policy.Resource).IsEqualTo(issued.Id(plan.PolicyKey));
                await Assert.That(persisted.Policy.Organization).IsEqualTo(root.Organization);
                await Assert.That(persisted.Policy.Project).IsEqualTo(issued.Id(EnvironmentPermissionPlan.Project));
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
                _ = await Original(ProjectMembershipOperations.UpdateProjectMembershipRoles(root.Organization, issued.Id(EnvironmentPermissionPlan.Project),
                    issued.Id(plan.ActorMembership(0)), [new(plan.Slug)]), true);
            }
            var retainedEvidence = original.Native.Evidence; await Witness(true);
            await Assert.That(original.Native.Evidence).IsEqualTo(retainedEvidence);
            await Assert.That(provider.Originals).IsEqualTo(boundary == "cancellation-boundary" ? 0 : 1);
        }
        finally
        {
            try { Check(await source.StepAsync(root, EnvironmentPermissionStep.Close, null, CancellationToken.None), EnvironmentPermissionStep.Close); }
            finally { issued?.Erase(); }
        }
        await InfisicalEnvironmentPermissionEffectTests.Clean(provider);
        void Check(EnvironmentPermissionPacket packet, EnvironmentPermissionStep step)
        {
            verifier.Check(packet, step); ownership.Check(packet, step);
            if (issued is not null) issued = issued with { Bindings = packet.Storage.Payload.Content.Bindings };
        }
        async Task<EnvironmentPermissionReceipt> Original<T>(ManagementRequest<T> request, bool setup = false) where T : notnull
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
        EnvironmentPermissionState Initial(EnvironmentPermissionRow row) => new(row.Key, issued!.Id(row.Target), issued.Id(row.Organization), issued.Id(row.Project), row.Name, row.Slug, 1.5, false, 1);
        async Task Witness(bool after)
        {
            var step = after ? EnvironmentPermissionStep.After : EnvironmentPermissionStep.Before;
            Check(await source.StepAsync(root, step, null, deadline.Token), step);
            if (after && template && applied)
            {
                foreach (var row in plan.Rows.Where(r => r.Window == "copy" && r.Action != EnvironmentPermissionAction.Create)) expected.Add(row.Key, Initial(row));
                var config = plan.ConfigurationEnvironment; expected.Add(config.Key, Initial(config));
            }
            var rows = plan.Rows.Where(r => r.Window == (!after ? "before" : template && applied ? "copy" : "after")).ToArray();
            var returned = new Dictionary<string, ProjectEnvironment>(); var submitted = new Dictionary<string, string>(); var paths = new Dictionary<string, string>();
            foreach (var row in rows)
            {
                var actor = issued!.Actors[row.Actor]; string organization = issued.Id(row.Organization), project = issued.Id(row.Project), target = issued.Id(row.Target);
                using var tokens = actor.Owned ? new MemberPermissionTokens(actor.Credential) : new MemberPermissionTokens(env.Tokens(
                    actor.Principal == root.Authorities.Runtime ? NativeIdentityRole.Runtime : NativeIdentityRole.Denied));
                var client = env.CreateManagementClient();
                using var request = row.Action switch
                {
                    EnvironmentPermissionAction.Read => ProjectOperations.GetEnvironment(organization, project, target),
                    EnvironmentPermissionAction.Create => ProjectOperations.CreateEnvironment(organization, project, row.Name, row.Slug, 1.5),
                    EnvironmentPermissionAction.Edit => ProjectOperations.UpdateEnvironment(organization, project, target, row.Name + "-edited", row.Slug + "-v2", 2.75),
                    _ => ProjectOperations.DeleteEnvironment(organization, project, target, permanently: true)
                };
                submitted.Add(row.Key, row.Action is EnvironmentPermissionAction.Create or EnvironmentPermissionAction.Edit ? request.Target.SecondaryId! : EnvironmentPermissionContract.RawHash([]));
                paths.Add(row.Key, "/api/v1/projects/" + project + "/environments" + (row.Action == EnvironmentPermissionAction.Create ? "" : "/" + target) +
                    (row.Action == EnvironmentPermissionAction.Delete ? "?hardDelete=true" : ""));
                bool allowed = row.Control == "selected" && (after && applied ? row.Action == action : !create && (int)row.Action == ((int)action + 1) % 4);
                var authority = new ManagementAuthority(client.Authority, tokens, organization, project);
                var receipt = request.IsMutation ? client.CreateReceipt(request) : null;
                var result = await client.ExecuteAsync(request, authority, authority.IssueGrant(request.OperationId, request.Target), receipt, deadline.Token);
                await Assert.That(result.Status).IsEqualTo(allowed ? SecretStatus.Success : SecretStatus.Denied);
                await Assert.That(tokens.Hash).IsEqualTo(actor.CredentialHash);
                if (receipt is not null) await Assert.That(receipt.Evidence).IsEqualTo(allowed ? DispatchEvidence.Applied : DispatchEvidence.Rejected);
                if (allowed) returned.Add(row.Key, result.Value);
            }
            var end = after ? EnvironmentPermissionStep.ObserveAfter : EnvironmentPermissionStep.ObserveBefore;
            var packet = await source.StepAsync(root, end, null, deadline.Token); Check(packet, end);
            await Assert.That(packet.Access.Payload.Content.Length).IsEqualTo(rows.Length);
            var join = packet.Membership.Payload.Content.Single(j => j.Membership == issued!.Id(plan.ActorMembership(0, after && template && applied)));
            bool active = !create || after && applied;
            await Assert.That(join.Assigned).IsEqualTo(active);
            await Assert.That(join.RoleId).IsEqualTo(active ? issued!.Id(after && template && applied ? EnvironmentPermissionPlan.CopiedRole : plan.PolicyKey) : "");
            await Assert.That(join.RoleSlug).IsEqualTo(active ? plan.Slug : "no-access");
            for (int index = 0; index < rows.Length; index++)
            {
                var row = rows[index]; var decision = packet.Access.Payload.Content[index]; var actor = issued!.Actors[row.Actor];
                await Assert.That(decision.Target).IsEqualTo(issued.Id(row.Target)); await Assert.That(decision.Action).IsEqualTo(row.Action);
                await Assert.That(decision.Actor).IsEqualTo(actor.Principal); await Assert.That(decision.Kind).IsEqualTo(actor.Kind);
                await Assert.That(decision.CredentialHash).IsEqualTo(actor.CredentialHash); await Assert.That(decision.Organization).IsEqualTo(issued.Id(row.Organization));
                await Assert.That(decision.Project).IsEqualTo(issued.Id(row.Project));
                var ingress = packet.Ingress.Payload.Content.Single(e => e.Request == decision.Request);
                await Assert.That(ingress.BodyHash).IsEqualTo(submitted[row.Key]); await Assert.That(ingress.Path).IsEqualTo(paths[row.Key]);
                await Assert.That(packet.Issuer.Payload.Content.Credentials.Any(c => c.Id == decision.CredentialId && c.Principal == decision.Actor && c.Kind == decision.Kind && c.Hash == decision.CredentialHash)).IsTrue();
                var before = expected.GetValueOrDefault(row.Key); var next = before;
                if (returned.TryGetValue(row.Key, out var value))
                {
                    int version = row.Action == EnvironmentPermissionAction.Edit ? 2 : 1;
                    var full = Initial(row) with { Name = version == 2 ? row.Name + "-edited" : row.Name, Slug = version == 2 ? row.Slug + "-v2" : row.Slug, Position = version == 2 ? 2.75 : 1.5, Version = version };
                    await Assert.That(value.Id).IsEqualTo(full.Target); await Assert.That(value.Name).IsEqualTo(full.Name);
                    await Assert.That(value.Slug).IsEqualTo(full.Slug); await Assert.That(value.Position).IsEqualTo(full.Position);
                    await Assert.That(value.SoftDeletedAtField.IsPresent && value.SoftDeletedAtField.IsNull && value.DeleteAfterField.IsPresent && value.DeleteAfterField.IsNull &&
                        value.DeletedByUserId.IsPresent && value.DeletedByUserId.IsNull && value.DeletedByIdentityId.IsPresent && value.DeletedByIdentityId.IsNull).IsTrue();
                    next = row.Action == EnvironmentPermissionAction.Delete ? null : full;
                }
                await Assert.That(packet.Storage.Payload.Content.Changes.Single(c => c.Request == decision.Request)).IsEqualTo(new EnvironmentPermissionChange(decision.Request, row.Key, before, next));
                if (next is null) expected.Remove(row.Key); else expected[row.Key] = next;
            }
            await Assert.That(packet.Storage.Payload.Content.Inventory.OrderBy(s => s.Row).SequenceEqual(expected.Values.OrderBy(s => s.Row))).IsTrue();
            // Independent full inventory and fresh typed readback, including projects
            // with zero active environments and the retained soft-deleted canary.
            foreach (string project in new[] { EnvironmentPermissionPlan.Project, EnvironmentPermissionPlan.OtherProject, EnvironmentPermissionPlan.CopyProject }.Select(issued!.Id).Where(p => p.Length > 0))
            {
                var client = env.CreateManagementClient(); using var list = ProjectOperations.GetProject(root.Organization, project);
                var authority = new ManagementAuthority(client.Authority, env.Tokens(NativeIdentityRole.Observer), root.Organization, project);
                var result = await client.ExecuteAsync(list, authority, authority.IssueGrant(list.OperationId, list.Target), cancellationToken: deadline.Token);
                var persisted = expected.Values.Where(s => s.Project == project).ToArray();
                await Assert.That(result.IsSuccess && result.Value.Environments.IsPresent && result.Value.DeletedEnvironments.IsPresent).IsTrue();
                await Assert.That(result.Value.Environments.Value.Select(r => r.Id).Order().SequenceEqual(persisted.Where(s => !s.Deleted).Select(s => s.Target).Order())).IsTrue();
                await Assert.That(result.Value.DeletedEnvironments.Value.Select(r => r.Id).Order().SequenceEqual(persisted.Where(s => s.Deleted).Select(s => s.Target).Order())).IsTrue();
                foreach (var reference in result.Value.DeletedEnvironments.Value)
                {
                    var state = persisted.Single(s => s.Target == reference.Id);
                    await Assert.That(reference.Name).IsEqualTo(state.Name); await Assert.That(reference.Slug).IsEqualTo(state.Slug);
                    await Assert.That(reference.SoftDeletedAt).IsEqualTo(state.SoftDeletedAt); await Assert.That(reference.DeleteAfter).IsEqualTo(state.DeleteAfter);
                    await Assert.That(reference.DeletedBy is { Type: ProjectDeletedByType.Identity } by && "identity:" + by.Id == state.DeletedBy).IsTrue();
                }
                foreach (var reference in result.Value.Environments.Value)
                {
                    var state = persisted.Single(s => s.Target == reference.Id);
                    await Assert.That(reference.Name).IsEqualTo(state.Name); await Assert.That(reference.Slug).IsEqualTo(state.Slug);
                    using var get = ProjectOperations.GetEnvironmentBySlug(root.Organization, project, state.Slug);
                    var fetched = await client.ExecuteAsync(get, authority, authority.IssueGrant(get.OperationId, get.Target), cancellationToken: deadline.Token);
                    await Assert.That(fetched.IsSuccess).IsTrue(); await Assert.That(fetched.Value.Id).IsEqualTo(state.Target);
                    await Assert.That(fetched.Value.Name).IsEqualTo(state.Name); await Assert.That(fetched.Value.Slug).IsEqualTo(state.Slug);
                    await Assert.That(fetched.Value.Position).IsEqualTo(state.Position);
                    await Assert.That(fetched.Value.SoftDeletedAtField.IsPresent && fetched.Value.SoftDeletedAtField.IsNull && fetched.Value.DeleteAfterField.IsPresent && fetched.Value.DeleteAfterField.IsNull).IsTrue();
                }
            }
        }
    }
}
