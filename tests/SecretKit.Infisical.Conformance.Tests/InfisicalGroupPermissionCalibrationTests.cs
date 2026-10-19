using SecretKit.Core;
using SecretKit.Infisical.Management;
using SecretKit.TestFixtures;

namespace SecretKit.Infisical.Conformance.Tests;

// Independent direct SDK/source calibration: no Effects, Client or Trial calls.
public sealed class InfisicalGroupPermissionCalibrationTests
{
    public static IEnumerable<(string Operation, string Variant, string Boundary)> Cases() => InfisicalGroupPermissionOriginalTests.Cases();
    [Test]
    [MethodDataSource(nameof(Cases))]
    public async Task DirectSdkCalibratesPersistedGroupsPolicyAndNativeAction(string operation, string variant, string boundary)
    {
        var action = InfisicalGroupPermissionGateTests.Action(variant);
        await using var provider = new InfisicalGroupPermissionFixture(); using var env = provider.Environment(operation, action);
        using var deadline = new CancellationTokenSource(TimeSpan.FromSeconds(45)); using var cap = SecretMaterial.FromText("group-capability");
        var root = provider.Root(operation, action, boundary); var plan = new GroupPermissionPlan(root); var source = provider.Source.CreateClient();
        using var verifier = new GroupPermissionVerifier(root); var ownership = new GroupPermissionOwnership(root, plan);
        GroupPermissionIssued? issued = null;
        bool org = operation.EndsWith("OrganizationRole", StringComparison.Ordinal), template = operation.Contains("ProjectTemplate", StringComparison.Ordinal),
            privilege = operation.Contains("IdentityPrivilegeChange", StringComparison.Ordinal), create = operation.Split('.').Last().StartsWith("Create", StringComparison.Ordinal),
            applied = boundary is not ("denied-authority" or "cancellation-boundary");
        try
        {
            Check(await source.StepAsync(root, GroupPermissionStep.Reserve, cap, deadline.Token), GroupPermissionStep.Reserve);
            await Assert.That(provider.Generated).IsEqualTo(0);
            var opened = await source.StepAsync(root, GroupPermissionStep.Open, null, deadline.Token);
            issued = new(opened.Owner.Payload.Content.Actors, opened.Storage.Payload.Content.Bindings); Check(opened, GroupPermissionStep.Open);
            await Witness(false);
            Check(await source.StepAsync(root, GroupPermissionStep.Arm, null, deadline.Token), GroupPermissionStep.Arm);
            GroupPermissionReceipt original;
            if (org)
            {
                var change = new OrganizationRoleChange(plan.Slug, plan.Slug,
                    permissions: [new(OrganizationRoleSubject.Groups, Enum.Parse<OrganizationRoleAction>(action.ToString()))]);
                original = await Original(create ? RoleChangeOperations.CreateOrganizationRole(root.Organization, change) :
                    RoleChangeOperations.UpdateOrganizationRole(root.Organization, issued.Id(plan.PolicyKey), change));
            }
            else
            {
                string[] names = plan.Rows.Where(r => r.Control == "selected").Select(r => r.Name).ToArray();
                var selected = Enum.Parse<ProjectRoleAction>(action.ToString());
                if (template)
                {
                    ProjectTemplateCondition[]? conditions = action == GroupPermissionAction.AssignRole ?
                        [new(RoleConditionField.GroupName, ProjectTemplateStringClause.Compare(included: names)),
                            new(RoleConditionField.AssignableRole, ProjectTemplateStringClause.Literal(plan.Role))] : null;
                    var config = new ProjectTemplateConfiguration(
                        [new(plan.Slug, plan.Slug, [new(ProjectRoleSubject.Groups, selected, conditions: conditions)])],
                        ProjectTemplateCollection<ProjectTemplateEnvironment>.FromValues([new("Witness", "witness", 1)]),
                        users: ProjectTemplateCollection<ProjectTemplateUser>.FromValues([new(plan.Username(plan.ActorKey(0)), [plan.Slug])]));
                    original = await Original(create ? ProjectTemplateOperations.CreateProjectTemplate(root.Organization, plan.Slug, configuration: config) :
                        ProjectTemplateOperations.UpdateProjectTemplate(root.Organization, issued.Id(plan.PolicyKey), configuration: config));
                }
                else
                {
                    RoleCondition[]? conditions = action == GroupPermissionAction.AssignRole ?
                        [new(RoleConditionField.GroupName, RoleStringClause.Compare(included: names)), new(RoleConditionField.AssignableRole, RoleStringClause.Literal(plan.Role))] : null;
                    ProjectRolePermission[] permissions = [new(ProjectRoleSubject.Groups, selected, conditions: conditions)];
                    if (privilege)
                    {
                        await Assert.That(issued.Actors[0].Principal).IsEqualTo(InfisicalGroupPermissionFixture.Authorities.Runtime);
                        await Assert.That(issued.Actors[0].Kind).IsEqualTo(MemberPermissionActorKind.Machine);
                        var selection = new LegacyPrivilegeSelection(root.Organization, issued.Id(GroupPermissionPlan.Project), plan.ProjectSlug,
                            issued.Actors[0].Principal, issued.Id(plan.ActorMembership(0)));
                        var change = new ProjectPrivilegeChange(permissions, PrivilegeLifetime.Permanent(), plan.Slug);
                        original = await Original(create ? IdentityPrivilegeChangeOperations.CreateProjectPrivilege(selection, change) :
                            IdentityPrivilegeChangeOperations.UpdateProjectPrivilege(selection, issued.Id(plan.PolicyKey), change));
                    }
                    else
                    {
                        var change = new ProjectRoleChange(plan.Slug, plan.Slug, permissions: permissions);
                        original = await Original(create ? RoleChangeOperations.CreateProjectRole(root.Organization, issued.Id(GroupPermissionPlan.Project), change) :
                            RoleChangeOperations.UpdateProjectRole(root.Organization, issued.Id(GroupPermissionPlan.Project), issued.Id(plan.PolicyKey), change));
                    }
                }
            }
            var settled = await source.StepAsync(root, GroupPermissionStep.Settle, null, deadline.Token); Check(settled, GroupPermissionStep.Settle);
            await Assert.That(settled.Ingress.Payload.Content.Length).IsEqualTo(boundary == "cancellation-boundary" ? 0 : 1);
            await Assert.That(settled.Policy.Payload.Content.Commits.Length).IsEqualTo(applied ? 1 : 0);
            if (applied)
            {
                var persisted = settled.Policy.Payload.Content.Commits.Single();
                await Assert.That(persisted.Request).IsEqualTo(settled.Ingress.Payload.Content.Single().Request);
                await Assert.That(persisted.Policy.Actor).IsEqualTo(issued.Actors[0].Principal);
                await Assert.That(persisted.Policy.Kind).IsEqualTo(privilege ? MemberPermissionActorKind.Machine : MemberPermissionActorKind.User);
                await Assert.That(persisted.Policy.Subject).IsEqualTo("groups");
                await Assert.That(persisted.Policy.Actions.SequenceEqual([GroupPermissionContract.Wire(action)])).IsTrue();
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
                else _ = await Original(ProjectMembershipOperations.UpdateProjectMembershipRoles(root.Organization, issued.Id(GroupPermissionPlan.Project),
                    issued.Id(plan.ActorMembership(0)), [new(plan.Slug)]), true);
            }
            await Witness(true);
        }
        finally
        {
            try { Check(await source.StepAsync(root, GroupPermissionStep.Close, null, CancellationToken.None), GroupPermissionStep.Close); }
            finally { issued?.Erase(); }
        }
        await InfisicalGroupPermissionEffectTests.Clean(provider);
        void Check(GroupPermissionPacket packet, GroupPermissionStep step)
        {
            verifier.Check(packet, step); ownership.Check(packet, step);
            if (issued is not null) issued = issued with { Bindings = packet.Storage.Payload.Content.Bindings };
        }
        async Task<GroupPermissionReceipt> Original<T>(ManagementRequest<T> request, bool setup = false) where T : notnull
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
        async Task Witness(bool after)
        {
            var step = after ? GroupPermissionStep.After : GroupPermissionStep.Before;
            Check(await source.StepAsync(root, step, null, deadline.Token), step);
            var rows = plan.Window(after, applied ? GroupPermissionOutcome.Applied : GroupPermissionOutcome.NonApplied);
            var returned = new List<(GroupPermissionRow Row, string Key, string Id)>();
            foreach (var row in rows)
            {
                var actor = issued!.Actors[row.Actor]; string organization = issued.Id(row.Organization), project = issued.Id(row.Project), group = issued.Id(row.Group);
                string role = row.Control == "role" ? "admin" : plan.Role;
                using var tokens = actor.Owned ? new MemberPermissionTokens(actor.Credential) : new MemberPermissionTokens(env.Tokens(
                    actor.Principal == root.Authorities.Runtime ? NativeIdentityRole.Runtime : NativeIdentityRole.Denied));
                var client = env.CreateManagementClient();
                string[] baselineActions = org ? ["read", "create", "edit", "delete", "grant-privileges", "add-identities", "add-members", "remove-members", "remove-identities"] :
                    ["read", "create", "delete", "assign-role"];
                string baseline = baselineActions[(Array.IndexOf(baselineActions, GroupPermissionContract.Wire(action)) + 1) % baselineActions.Length];
                bool allowed = row.Control == "selected" && (after && applied ? row.Action == action : !create && GroupPermissionContract.Wire(row.Action) == baseline);
                if (!org && row.Action == GroupPermissionAction.AssignRole)
                {
                    using var request = MembershipOperations.UpdateProjectGroupRoles(organization, project, group, issued.Id(row.Membership), [new(role)]);
                    var result = await Send(request); if (result.IsSuccess) await Assert.That(result.Value.Items.Single().Role).IsEqualTo(plan.Role);
                }
                else if (!org)
                {
                    using var request = row.Action switch
                    {
                        GroupPermissionAction.Read => MembershipOperations.GetProjectGroup(organization, project, group),
                        GroupPermissionAction.Create => MembershipOperations.AddProjectGroup(organization, project, group, new MembershipRoleSelection(role: "no-access")),
                        _ => MembershipOperations.RemoveProjectGroup(organization, project, group)
                    };
                    var result = await Send(request);
                    if (result.IsSuccess)
                    {
                        await Assert.That(result.Value.PrincipalId).IsEqualTo(group); returned.Add((row, row.Membership, result.Value.Id));
                    }
                }
                else if (row.Action is GroupPermissionAction.AddMembers or GroupPermissionAction.RemoveMembers)
                {
                    using var request = row.Action == GroupPermissionAction.AddMembers ? ScopedAccessOperations.AddGroupUser(organization, group, plan.Username(row.User)) :
                        ScopedAccessOperations.RemoveGroupUser(organization, group, plan.Username(row.User));
                    var result = await Send(request); if (result.IsSuccess) await Assert.That(result.Value.Id).IsEqualTo(issued.Id(row.User));
                }
                else if (row.Action is GroupPermissionAction.AddIdentities or GroupPermissionAction.RemoveIdentities)
                {
                    using var request = row.Action == GroupPermissionAction.AddIdentities ? ScopedAccessOperations.AddGroupIdentity(organization, group, issued.Id(row.Identity)) :
                        ScopedAccessOperations.RemoveGroupIdentity(organization, group, issued.Id(row.Identity));
                    var result = await Send(request); if (result.IsSuccess) returned.Add((row, row.IdentityLink, result.Value.Id));
                }
                else
                {
                    using var request = row.Action switch
                    {
                        GroupPermissionAction.Read => ScopedAccessOperations.GetGroup(organization, group),
                        GroupPermissionAction.Create => ScopedAccessOperations.CreateGroup(organization, row.Name, row.Name, "no-access"),
                        GroupPermissionAction.Edit => ScopedAccessOperations.UpdateGroup(organization, group, name: row.Name + "-edited"),
                        GroupPermissionAction.GrantPrivileges => ScopedAccessOperations.UpdateGroup(organization, group, role: role),
                        _ => ScopedAccessOperations.DeleteGroup(organization, group)
                    };
                    var result = await Send(request);
                    if (result.IsSuccess)
                    {
                        returned.Add((row, row.Group, result.Value.Id));
                        await Assert.That(result.Value.Name).IsEqualTo(row.Action == GroupPermissionAction.Edit ? row.Name + "-edited" : row.Name);
                    }
                }
                async ValueTask<SecretOutcome<T>> Send<T>(ManagementRequest<T> request) where T : notnull
                {
                    var authority = new ManagementAuthority(client.Authority, tokens, organization, org ? null : project);
                    var receipt = request.IsMutation ? client.CreateReceipt(request) : null;
                    var result = await client.ExecuteAsync(request, authority, authority.IssueGrant(request.OperationId, request.Target), receipt, deadline.Token);
                    await Assert.That(result.Status).IsEqualTo(allowed ? SecretStatus.Success : SecretStatus.Denied);
                    await Assert.That(tokens.Hash).IsEqualTo(actor.CredentialHash);
                    if (receipt is not null) await Assert.That(receipt.Evidence).IsEqualTo(allowed ? DispatchEvidence.Applied : DispatchEvidence.Rejected);
                    return result;
                }
            }
            var end = after ? GroupPermissionStep.ObserveAfter : GroupPermissionStep.ObserveBefore;
            var packet = await source.StepAsync(root, end, null, deadline.Token); Check(packet, end);
            await Assert.That(packet.Access.Payload.Content.Length).IsEqualTo(rows.Length);
            foreach (var (row, key, id) in returned)
            {
                await Assert.That(issued!.Id(key)).IsEqualTo(id);
                var decision = packet.Access.Payload.Content.Single(d => d.Group == issued.Id(row.Group) && d.Action == row.Action);
                await Assert.That(packet.Issuer.Payload.Content.Credentials.Any(c => c.Id == decision.CredentialId && c.Principal == decision.Actor &&
                    c.Kind == decision.Kind && c.Hash == decision.CredentialHash)).IsTrue();
                var change = packet.Storage.Payload.Content.Changes.Single(c => c.Request == decision.Request);
                await Assert.That(change.Row).IsEqualTo(row.Key);
                if (row.Action == GroupPermissionAction.Delete) await Assert.That(change.After).IsNull();
                else await Assert.That(change.After!.Group).IsEqualTo(issued.Id(row.Group));
            }
        }
    }
}
