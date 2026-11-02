using SecretKit.Core;
using SecretKit.Infisical.Management;
using SecretKit.TestFixtures;

namespace SecretKit.Infisical.Conformance.Tests;

// Independent direct SDK calibration. No MemberPermissionEffects, Client or Trial
// calls: selected wire factories mutate provider policy, direct native membership
// operations measure it, and independently signed storage is compared afterward.
public sealed class InfisicalMemberPermissionCalibrationTests
{
    public static IEnumerable<(string Operation, string Variant, string Boundary)> Cases() =>
        InfisicalMemberPermissionGateTests.Cases().Where(c =>
            MemberPermissionContract.Gate(MemberPermissionContract.Scope(c.Operation), InfisicalMemberPermissionGateTests.Action(c.Variant)) is null);
    [Test]
    [MethodDataSource(nameof(Cases))]
    public async Task DirectSdkAndSourceCalibrateEachSupportedActionBoundary(string operation, string variant, string boundary)
    {
        var action = InfisicalMemberPermissionGateTests.Action(variant);
        await using var provider = new InfisicalMemberPermissionFixture();
        using var env = provider.Environment(operation, action);
        using var deadline = new CancellationTokenSource(TimeSpan.FromSeconds(45));
        using var capability = SecretMaterial.FromText("member-capability");
        var root = provider.Root(operation, action, boundary);
        var source = provider.Source.CreateClient();
        using var verifier = new MemberPermissionVerifier(root);
        MemberPermissionIssued? issued = null;
        bool create = operation.Split('.').Last().StartsWith("Create", StringComparison.Ordinal);
        bool organization = operation.EndsWith("OrganizationRole", StringComparison.Ordinal);
        bool template = operation.Contains("ProjectTemplate", StringComparison.Ordinal);
        bool privilege = operation.Contains("IdentityPrivilegeChange", StringComparison.Ordinal);
        bool applied = boundary is not ("denied-authority" or "cancellation-boundary");
        // Recovery retained before Reserve and keyed solely by original root.
        try
        {
            Check(await source.StepAsync(root, MemberPermissionStep.Reserve, capability, deadline.Token), MemberPermissionStep.Reserve);
            var opened = await source.StepAsync(root, MemberPermissionStep.Open, null, deadline.Token);
            issued = opened.Owner.Payload.Content.Issued!;
            Check(opened, MemberPermissionStep.Open);
            await Witness(false);
            Check(await source.StepAsync(root, MemberPermissionStep.Arm, null, deadline.Token), MemberPermissionStep.Arm);
            MemberPermissionReceipt original;
            if (organization)
            {
                var change = new OrganizationRoleChange(issued.PolicySlug, issued.PolicySlug, permissions:
                    [new(OrganizationRoleSubject.Member, action switch
                    {
                        MemberPermissionAction.Read => OrganizationRoleAction.Read,
                        MemberPermissionAction.Edit => OrganizationRoleAction.Edit,
                        MemberPermissionAction.Delete => OrganizationRoleAction.Delete,
                        MemberPermissionAction.GrantPrivileges => OrganizationRoleAction.GrantPrivileges,
                        _ => throw new InvalidOperationException()
                    })]);
                original = await Original(create ? RoleChangeOperations.CreateOrganizationRole(root.Organization, change) :
                    RoleChangeOperations.UpdateOrganizationRole(root.Organization, issued.PolicyId, change));
            }
            else
            {
                ProjectRoleAction selected = action switch
                {
                    MemberPermissionAction.Read => ProjectRoleAction.Read,
                    MemberPermissionAction.Create => ProjectRoleAction.Create,
                    MemberPermissionAction.Delete => ProjectRoleAction.Delete,
                    MemberPermissionAction.AssignRole => ProjectRoleAction.AssignRole,
                    _ => throw new InvalidOperationException()
                };
                string[] emails = issued.Rows.Where(r => r.Control == "selected").Select(r => r.User.Email).ToArray();
                if (template)
                {
                    ProjectTemplateCondition[]? conditions = action == MemberPermissionAction.AssignRole ?
                        [new(RoleConditionField.UserEmail, ProjectTemplateStringClause.Compare(included: emails)),
                            new(RoleConditionField.AssignableRole, ProjectTemplateStringClause.Literal(issued.AssignedRole))] : null;
                    var config = new ProjectTemplateConfiguration(
                        [new(issued.PolicySlug, issued.PolicySlug, [new(ProjectRoleSubject.Member, selected, conditions: conditions)])],
                        ProjectTemplateCollection<ProjectTemplateEnvironment>.FromValues([new("Witness", "witness", 1)]),
                        users: ProjectTemplateCollection<ProjectTemplateUser>.FromValues([new(issued.Principals[0].Username, [issued.PolicySlug])]));
                    original = await Original(create ?
                        ProjectTemplateOperations.CreateProjectTemplate(root.Organization, issued.PolicySlug, configuration: config) :
                        ProjectTemplateOperations.UpdateProjectTemplate(root.Organization, issued.TemplateId, configuration: config));
                }
                else
                {
                    RoleCondition[]? conditions = action == MemberPermissionAction.AssignRole ?
                        [new(RoleConditionField.UserEmail, RoleStringClause.Compare(included: emails)),
                            new(RoleConditionField.AssignableRole, RoleStringClause.Literal(issued.AssignedRole))] : null;
                    ProjectRolePermission[] permissions = [new(ProjectRoleSubject.Member, selected, conditions: conditions)];
                    if (privilege)
                    {
                        var actor = issued.Principals[0];
                        await Assert.That(actor.Kind).IsEqualTo(MemberPermissionActorKind.Machine);
                        await Assert.That(actor.Id).IsEqualTo(InfisicalMemberPermissionFixture.Authorities.Runtime);
                        var selection = new LegacyPrivilegeSelection(root.Organization, issued.Project, issued.ProjectSlug, actor.Id, actor.ProjectMembership);
                        var change = new ProjectPrivilegeChange(permissions, PrivilegeLifetime.Permanent(), issued.PolicySlug);
                        original = await Original(create ? IdentityPrivilegeChangeOperations.CreateProjectPrivilege(selection, change) :
                            IdentityPrivilegeChangeOperations.UpdateProjectPrivilege(selection, issued.PolicyId, change));
                    }
                    else
                    {
                        var change = new ProjectRoleChange(issued.PolicySlug, issued.PolicySlug, permissions: permissions);
                        original = await Original(create ? RoleChangeOperations.CreateProjectRole(root.Organization, issued.Project, change) :
                            RoleChangeOperations.UpdateProjectRole(root.Organization, issued.Project, issued.PolicyId, change));
                    }
                }
            }
            var settled = await source.StepAsync(root, MemberPermissionStep.Settle, null, deadline.Token);
            Check(settled, MemberPermissionStep.Settle);
            await Assert.That(settled.Ingress.Payload.Content.Length).IsEqualTo(boundary == "cancellation-boundary" ? 0 : 1);
            await Assert.That(settled.Policy.Payload.Content.Commits.Length).IsEqualTo(applied ? 1 : 0);
            if (applied)
            {
                var persisted = settled.Policy.Payload.Content.Commits.Single().Policy;
                await Assert.That(persisted.ActorId).IsEqualTo(issued.Principals[0].Id);
                await Assert.That(persisted.ActorKind).IsEqualTo(privilege ? MemberPermissionActorKind.Machine : MemberPermissionActorKind.User);
                await Assert.That(persisted.Actions.SequenceEqual([MemberPermissionContract.Wire(action)])).IsTrue();
            }
            await Assert.That(original.Native.Evidence).IsEqualTo(boundary switch
            {
                "denied-authority" => DispatchEvidence.Rejected,
                "cancellation-boundary" => DispatchEvidence.NotDispatched,
                "lost-response-no-replay" => DispatchEvidence.PossiblyDispatched,
                _ => DispatchEvidence.Applied
            });
            if (applied && template)
                _ = await Original(ProjectOperations.CreateProject(root.Organization, issued.CopySlug, issued.CopySlug,
                    template: issued.PolicySlug, createDefaultEnvironments: false), setup: true);
            else if (applied && create && !privilege)
            {
                if (organization)
                    _ = await Original(OrganizationMembershipOperations.UpdateOrganizationMembership(root.Organization,
                        issued.Principals[0].OrganizationMembership, role: issued.PolicySlug), setup: true);
                else
                    _ = await Original(ProjectMembershipOperations.UpdateProjectMembershipRoles(root.Organization, issued.Project,
                        issued.Principals[0].ProjectMembership, [new(issued.PolicySlug)]), setup: true);
            }
            await Witness(true);
        }
        finally
        {
            try
            {
                var closed = await source.StepAsync(root, MemberPermissionStep.Close, null, CancellationToken.None);
                Check(closed, MemberPermissionStep.Close);
                await Assert.That(closed.Owner.Payload.Content.Remaining.Length).IsEqualTo(0);
                await Assert.That(closed.Issuer.Payload.Content.Length).IsEqualTo(0);
                await Assert.That(closed.Membership.Payload.Content.Length).IsEqualTo(0);
            }
            finally { issued?.Erase(); }
        }
        await InfisicalMemberPermissionEffectTests.Clean(provider);

        void Check(MemberPermissionPacket packet, MemberPermissionStep step)
        {
            _ = verifier.Journal(packet.Owner, packet, MemberPermissionJournal.Ownership, step);
            _ = verifier.Journal(packet.Ingress, packet, MemberPermissionJournal.Ingress, step);
            _ = verifier.Journal(packet.Policy, packet, MemberPermissionJournal.Policy, step);
            _ = verifier.Journal(packet.Storage, packet, MemberPermissionJournal.Storage, step);
            _ = verifier.Journal(packet.Issuer, packet, MemberPermissionJournal.Issuer, step);
            _ = verifier.Journal(packet.Membership, packet, MemberPermissionJournal.Membership, step);
            _ = verifier.Journal(packet.Access, packet, MemberPermissionJournal.Access, step);
        }
        async Task<MemberPermissionReceipt> Original<T>(ManagementRequest<T> request, bool setup = false) where T : notnull
        {
            using (request)
            {
                var client = env.CreateManagementClient(); var receipt = client.CreateReceipt(request);
                var role = setup ? NativeIdentityRole.Setup : boundary == "denied-authority" ? NativeIdentityRole.Denied : NativeIdentityRole.Administrative;
                var barrier = !setup && boundary == "cancellation-boundary" ? new ProjectTokenBarrier(env.Tokens(role)) : null;
                using var cancellation = CancellationTokenSource.CreateLinkedTokenSource(deadline.Token);
                using var loss = !setup && boundary == "lost-response-no-replay" ? new ProjectResponseBoundary(env.Origin, cancellation) : null;
                using var scope = loss?.Enter();
                var authority = new ManagementAuthority(client.Authority, barrier ?? env.Tokens(role), root.Organization, request.Target.ProjectId);
                Task? signal = barrier?.Entered;
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
            var start = after ? MemberPermissionStep.After : MemberPermissionStep.Before;
            var opened = await source.StepAsync(root, start, null, deadline.Token); Check(opened, start);
            var states = opened.Storage.Payload.Content.Inventory.ToDictionary(s => s.Membership);
            var rows = issued!.Rows.Where(r => r.Window == (!after ? "before" : template && applied ? "copy" : "after")).ToArray();
            MemberPermissionAction[] supported = organization ?
                [MemberPermissionAction.Read, MemberPermissionAction.Edit, MemberPermissionAction.Delete, MemberPermissionAction.GrantPrivileges] :
                [MemberPermissionAction.Read, MemberPermissionAction.Create, MemberPermissionAction.Delete, MemberPermissionAction.AssignRole];
            var baseline = supported[(Array.IndexOf(supported, action) + 1) % supported.Length];
            foreach (var row in rows)
            {
                var actor = issued.Principals[row.Actor];
                using var tokens = actor.Owned ? new MemberPermissionTokens(actor.Credential) : new MemberPermissionTokens(
                    env.Tokens(actor.Id == root.Authorities.Runtime ? NativeIdentityRole.Runtime : NativeIdentityRole.Denied));
                var client = env.CreateManagementClient();
                bool allowed = row.Control == "selected" && (after && applied ? row.Action == action : !create && row.Action == baseline);
                if (organization)
                {
                    if (row.Action == MemberPermissionAction.Read)
                    {
                        using var request = OrganizationMembershipOperations.ListOrganizationMemberships(row.Organization);
                        var result = await Send(request);
                        if (result.IsSuccess)
                            await Assert.That(result.Value.Items.Select(m => m.Id).Order().SequenceEqual(
                                states.Values.Where(s => s.Organization == row.Organization).Select(s => s.Membership).Order())).IsTrue();
                    }
                    else
                    {
                        using var request = row.Action == MemberPermissionAction.Edit ?
                            OrganizationMembershipOperations.UpdateOrganizationMembership(row.Organization, row.Membership, isActive: false) :
                            row.Action == MemberPermissionAction.GrantPrivileges ?
                                OrganizationMembershipOperations.UpdateOrganizationMembership(row.Organization, row.Membership, role: issued.AssignedRole) :
                                OrganizationMembershipOperations.DeleteOrganizationMembership(row.Organization, row.Membership);
                        var result = await Send(request);
                        if (result.IsSuccess) await Assert.That(result.Value.UserId).IsEqualTo(row.User.Id);
                    }
                }
                else if (row.Action == MemberPermissionAction.Read)
                {
                    using var request = ProjectMembershipOperations.InspectProjectMembershipByUsername(row.Organization, row.Project, row.User.Username);
                    var result = await Send(request);
                    if (result.IsSuccess) await Assert.That(result.Value.UserId).IsEqualTo(row.User.Id);
                }
                else if (row.Action == MemberPermissionAction.AssignRole)
                {
                    using var request = ProjectMembershipOperations.UpdateProjectMembershipRoles(row.Organization, row.Project, row.Membership, [new(issued.AssignedRole)]);
                    var result = await Send(request);
                    if (result.IsSuccess) await Assert.That(result.Value.Items.Single().Role).IsEqualTo(issued.AssignedRole);
                }
                else
                {
                    using var request = row.Action == MemberPermissionAction.Create ?
                        MembershipMutationOperations.InviteProjectMembers(row.Organization, row.Project, new(usernames: [row.User.Username]), ["no-access"]) :
                        MembershipMutationOperations.RemoveProjectMembers(row.Organization, row.Project, new(usernames: [row.User.Username]));
                    var result = await Send(request);
                    if (result.IsSuccess) await Assert.That(result.Value.Items.Single().UserId).IsEqualTo(row.User.Id);
                }
                if (allowed)
                {
                    switch (row.Action)
                    {
                        case MemberPermissionAction.Create: states.Add(row.Membership, MemberPermissionContract.Initial(row)); break;
                        case MemberPermissionAction.Delete: states.Remove(row.Membership); break;
                        case MemberPermissionAction.Edit: states[row.Membership] = states[row.Membership] with { Active = false, Version = 2 }; break;
                        case MemberPermissionAction.AssignRole:
                        case MemberPermissionAction.GrantPrivileges: states[row.Membership] = states[row.Membership] with { Role = issued.AssignedRole, Version = 2 }; break;
                    }
                }
                async ValueTask<SecretOutcome<T>> Send<T>(ManagementRequest<T> request) where T : notnull
                {
                    var authority = new ManagementAuthority(client.Authority, tokens, row.Organization, organization ? null : row.Project);
                    var receipt = request.IsMutation ? client.CreateReceipt(request) : null;
                    var result = await client.ExecuteAsync(request, authority, authority.IssueGrant(request.OperationId, request.Target), receipt, deadline.Token);
                    await Assert.That(result.Status).IsEqualTo(allowed ? SecretStatus.Success : SecretStatus.Denied);
                    await Assert.That(tokens.Hash).IsEqualTo(actor.CredentialHash);
                    if (receipt is not null) await Assert.That(receipt.Evidence).IsEqualTo(allowed ? DispatchEvidence.Applied : DispatchEvidence.Rejected);
                    return result;
                }
            }
            var end = after ? MemberPermissionStep.ObserveAfter : MemberPermissionStep.ObserveBefore;
            var packet = await source.StepAsync(root, end, null, deadline.Token); Check(packet, end);
            await Assert.That(packet.Storage.Payload.Content.Inventory.OrderBy(s => s.Membership)
                .SequenceEqual(states.Values.OrderBy(s => s.Membership))).IsTrue();
            await Assert.That(packet.Access.Payload.Content.Length).IsEqualTo(rows.Length);
            foreach (var decision in packet.Access.Payload.Content)
                await Assert.That(packet.Issuer.Payload.Content.Contains(new(decision.CredentialId,
                    decision.ActorId, decision.ActorKind, decision.CredentialHash, decision.ActorKind == MemberPermissionActorKind.User))).IsTrue();
        }
    }
}
