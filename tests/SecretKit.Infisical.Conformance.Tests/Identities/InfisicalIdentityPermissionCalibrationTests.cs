using SecretKit.Core;
using SecretKit.Infisical.Management;
using SecretKit.TestFixtures;

namespace SecretKit.Infisical.Conformance.Tests;

// Independent direct SDK/source calibration: no Effects, Client or Trial calls.
public sealed class InfisicalIdentityPermissionCalibrationTests
{
    public static IEnumerable<(string Operation, string Variant, string Boundary)> Cases() => InfisicalIdentityPermissionOriginalTests.Cases();
    [Test]
    [MethodDataSource(nameof(Cases))]
    public async Task DirectSdkCalibratesPersistedIdentityPolicyAndNativeAction(string operation, string variant, string boundary)
    {
        var action = InfisicalIdentityPermissionGateTests.Action(variant);
        await using var provider = new InfisicalIdentityPermissionFixture(); using var env = provider.Environment(operation, action);
        using var deadline = new CancellationTokenSource(TimeSpan.FromSeconds(45)); using var cap = SecretMaterial.FromText("identity-capability");
        var root = provider.Root(operation, action, boundary); var plan = new IdentityPermissionPlan(root); var source = provider.Source.CreateClient();
        using var verifier = new IdentityPermissionVerifier(root); var ownership = new IdentityPermissionOwnership(root, plan);
        IdentityPermissionIssued? issued = null; IdentityPermissionCredential[]? actorInventory = null;
        bool org = operation.EndsWith("OrganizationRole", StringComparison.Ordinal), template = operation.Contains("ProjectTemplate", StringComparison.Ordinal),
            privilege = operation.Contains("IdentityPrivilegeChange", StringComparison.Ordinal), create = operation.Split('.').Last().StartsWith("Create", StringComparison.Ordinal),
            applied = boundary is not ("denied-authority" or "cancellation-boundary");
        try
        {
            Check(await source.StepAsync(root, IdentityPermissionStep.Reserve, cap, deadline.Token), IdentityPermissionStep.Reserve);
            await Assert.That(provider.Generated).IsEqualTo(0);
            var opened = await source.StepAsync(root, IdentityPermissionStep.Open, null, deadline.Token);
            issued = new(opened.Owner.Payload.Content.Actors, opened.Storage.Payload.Content.Bindings, opened.Owner.Payload.Content.Targets); Check(opened, IdentityPermissionStep.Open); actorInventory = opened.Issuer.Payload.Content.Credentials.ToArray();
            await Witness(false);
            Check(await source.StepAsync(root, IdentityPermissionStep.Arm, null, deadline.Token), IdentityPermissionStep.Arm);
            IdentityPermissionReceipt original;
            if (org)
            {
                var change = new OrganizationRoleChange(plan.Slug, plan.Slug,
                    permissions: [new(OrganizationRoleSubject.Identity, Enum.Parse<OrganizationRoleAction>(action.ToString()))]);
                original = await Original(create ? RoleChangeOperations.CreateOrganizationRole(root.Organization, change) :
                    RoleChangeOperations.UpdateOrganizationRole(root.Organization, issued.Id(plan.PolicyKey), change));
            }
            else
            {
                string[] names = plan.Rows.Where(r => r.Control == "selected" && r.Action == action).Select(r => issued.Id(r.Identity)).Where(id => id.Length > 0).ToArray();
                var selected = Enum.Parse<ProjectRoleAction>(action.ToString());
                if (template)
                {
                    ProjectTemplateCondition[]? conditions = action == IdentityPermissionAction.AssignRole ?
                        [new(RoleConditionField.IdentityId, ProjectTemplateStringClause.Compare(included: names)),
                            new(RoleConditionField.AssignableRole, ProjectTemplateStringClause.Literal(plan.Role))] : action == IdentityPermissionAction.AssignAdditionalPrivileges ?
                            [new(RoleConditionField.IdentityId, ProjectTemplateStringClause.Compare(included: names)),
                                new(RoleConditionField.AssignableSubject, ProjectTemplateStringClause.Literal("identity")),
                                new(RoleConditionField.AssignableAction, ProjectTemplateStringClause.Literal("read"))] : null;
                    var config = new ProjectTemplateConfiguration(
                        [new(plan.Slug, plan.Slug, [new(ProjectRoleSubject.Identity, selected, conditions: conditions)])],
                        ProjectTemplateCollection<ProjectTemplateEnvironment>.FromValues([new("Witness", "witness", 1)]),
                        users: ProjectTemplateCollection<ProjectTemplateUser>.FromValues([new(plan.Username(plan.ActorKey(0)), [plan.Slug])]));
                    original = await Original(create ? ProjectTemplateOperations.CreateProjectTemplate(root.Organization, plan.Slug, configuration: config) :
                        ProjectTemplateOperations.UpdateProjectTemplate(root.Organization, issued.Id(plan.PolicyKey), configuration: config));
                }
                else
                {
                    RoleCondition[]? conditions = action == IdentityPermissionAction.AssignRole ?
                        [new(RoleConditionField.IdentityId, RoleStringClause.Compare(included: names)), new(RoleConditionField.AssignableRole, RoleStringClause.Literal(plan.Role))] : action == IdentityPermissionAction.AssignAdditionalPrivileges ?
                        [new(RoleConditionField.IdentityId, RoleStringClause.Compare(included: names)),
                            new(RoleConditionField.AssignableSubject, RoleStringClause.Literal("identity")),
                            new(RoleConditionField.AssignableAction, RoleStringClause.Literal("read"))] : null;
                    ProjectRolePermission[] permissions = [new(ProjectRoleSubject.Identity, selected, conditions: conditions)];
                    if (privilege)
                    {
                        await Assert.That(issued.Actors[0].Principal).IsEqualTo(InfisicalIdentityPermissionFixture.Authorities.Runtime);
                        await Assert.That(issued.Actors[0].Kind).IsEqualTo(MemberPermissionActorKind.Machine);
                        var selection = new LegacyPrivilegeSelection(root.Organization, issued.Id(IdentityPermissionPlan.Project), plan.ProjectSlug,
                            issued.Actors[0].Principal, issued.Id(plan.ActorMembership(0)));
                        var change = new ProjectPrivilegeChange(permissions, PrivilegeLifetime.Permanent(), plan.Slug);
                        original = await Original(create ? IdentityPrivilegeChangeOperations.CreateProjectPrivilege(selection, change) :
                            IdentityPrivilegeChangeOperations.UpdateProjectPrivilege(selection, issued.Id(plan.PolicyKey), change));
                    }
                    else
                    {
                        var change = new ProjectRoleChange(plan.Slug, plan.Slug, permissions: permissions);
                        original = await Original(create ? RoleChangeOperations.CreateProjectRole(root.Organization, issued.Id(IdentityPermissionPlan.Project), change) :
                            RoleChangeOperations.UpdateProjectRole(root.Organization, issued.Id(IdentityPermissionPlan.Project), issued.Id(plan.PolicyKey), change));
                    }
                }
            }
            var settled = await source.StepAsync(root, IdentityPermissionStep.Settle, null, deadline.Token); Check(settled, IdentityPermissionStep.Settle);
            await Assert.That(settled.Ingress.Payload.Content.Length).IsEqualTo(boundary == "cancellation-boundary" ? 0 : 1);
            await Assert.That(settled.Policy.Payload.Content.Commits.Length).IsEqualTo(applied ? 1 : 0);
            if (applied)
            {
                var persisted = settled.Policy.Payload.Content.Commits.Single();
                await Assert.That(persisted.Request).IsEqualTo(settled.Ingress.Payload.Content.Single().Request);
                await Assert.That(persisted.Policy.Actor).IsEqualTo(issued.Actors[0].Principal);
                await Assert.That(persisted.Policy.Kind).IsEqualTo(privilege ? MemberPermissionActorKind.Machine : MemberPermissionActorKind.User);
                await Assert.That(persisted.Policy.Subject).IsEqualTo("identity");
                await Assert.That(persisted.Policy.Actions.SequenceEqual([IdentityPermissionContract.Wire(action)])).IsTrue();
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
                else _ = await Original(ProjectMembershipOperations.UpdateProjectMembershipRoles(root.Organization, issued.Id(IdentityPermissionPlan.Project),
                    issued.Id(plan.ActorMembership(0)), [new(plan.Slug)]), true);
            }
            await Witness(true);
        }
        finally
        {
            try { Check(await source.StepAsync(root, IdentityPermissionStep.Close, null, CancellationToken.None), IdentityPermissionStep.Close); }
            finally { issued?.Erase(); }
        }
        await InfisicalIdentityPermissionEffectTests.Clean(provider);
        void Check(IdentityPermissionPacket packet, IdentityPermissionStep step)
        {
            verifier.Check(packet, step); ownership.Check(packet, step);
            if (actorInventory is not null && !packet.Issuer.Payload.Content.Credentials.SequenceEqual(actorInventory))
                throw new NativeCaseFailureException("effect-mismatch");
            if (issued is not null) issued = issued with
            {
                Bindings = packet.Storage.Payload.Content.Bindings,
                Targets = step == IdentityPermissionStep.After ? [.. issued.Targets, .. packet.Owner.Payload.Content.Targets] : issued.Targets
            };
        }
        async Task<IdentityPermissionReceipt> Original<T>(ManagementRequest<T> request, bool setup = false) where T : notnull
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
            var step = after ? IdentityPermissionStep.After : IdentityPermissionStep.Before;
            Check(await source.StepAsync(root, step, null, deadline.Token), step);
            var rows = plan.Window(after, applied ? IdentityPermissionOutcome.Applied : IdentityPermissionOutcome.NonApplied);
            var returned = new List<(IdentityPermissionRow Row, string Key, string Id)>();
            foreach (var row in rows)
            {
                var actor = issued!.Actors[row.Actor]; string organization = issued.Id(row.Organization), project = issued.Id(row.Project), identity = issued.Id(row.Identity);
                string role = row.Control == "role" ? "admin" : plan.Role;
                using var tokens = actor.Owned ? new MemberPermissionTokens(actor.Credential) : new MemberPermissionTokens(env.Tokens(
                    actor.Principal == root.Authorities.Runtime ? NativeIdentityRole.Runtime : NativeIdentityRole.Denied));
                var client = env.CreateManagementClient();
                string[] baselineActions = org ? ["read", "create", "edit", "delete", "grant-privileges", "revoke-auth", "edit-auth", "create-token", "get-token", "delete-token"] :
                    ["read", "create", "edit", "delete", "assign-role", "assign-additional-privileges", "revoke-auth", "edit-auth", "create-token", "get-token", "delete-token"];
                string baseline = baselineActions[(Array.IndexOf(baselineActions, IdentityPermissionContract.Wire(action)) + 1) % baselineActions.Length];
                bool allowed = row.Control == "selected" && (after && applied ? row.Action == action : !create && IdentityPermissionContract.Wire(row.Action) == baseline);
                if (IdentityPermissionContract.TokenAction(row.Action))
                {
                    var held = issued.Targets.SingleOrDefault(t => t.Row == row.Key);
                    if (held is not null) await Probe(held.Material);
                    if (row.Action == IdentityPermissionAction.CreateToken)
                    {
                        using var request = IdentityAuthenticationOperations.CreateToken(organization, identity, row.Name);
                        var result = await Send(request);
                        if (result.IsSuccess)
                        {
                            using var creation = result.Value;
                            await source.CaptureAsync(root, row.Key, creation.Metadata.Id, creation.AccessToken, deadline.Token);
                            char[] characters = creation.AccessToken.ExportCharacters(); byte[] bytes;
                            try { bytes = System.Text.Encoding.UTF8.GetBytes(characters); } finally { Array.Clear(characters); }
                            try { await Probe(bytes); } finally { System.Security.Cryptography.CryptographicOperations.ZeroMemory(bytes); }
                            returned.Add((row, row.Token, creation.Metadata.Id));
                        }
                    }
                    else if (row.Action == IdentityPermissionAction.GetToken)
                    {
                        using var request = IdentityAuthenticationOperations.ListTokens(organization, identity); var result = await Send(request);
                        if (result.IsSuccess) { await Assert.That(result.Value.IsComplete).IsTrue(); await Assert.That(result.Value.Items.Single().Id).IsEqualTo(issued.Id(row.Token)); }
                    }
                    else if (row.Action == IdentityPermissionAction.DeleteToken)
                    { using var request = IdentityAuthenticationOperations.RevokeToken(organization, issued.Id(row.Token)); _ = await Send(request); }
                    else
                    {
                        using var request = row.Action == IdentityPermissionAction.EditAuth ? IdentityAuthenticationOperations.UpdateTokenAuth(organization, identity, new(accessTokenTTL: 900)) :
                            IdentityAuthenticationOperations.DeleteTokenAuth(organization, identity); _ = await Send(request);
                    }
                    if (held is not null) await Probe(held.Material);
                }
                else if (row.Action == IdentityPermissionAction.AssignAdditionalPrivileges)
                {
                    var selection = new LegacyPrivilegeSelection(organization, project, plan.ProjectSlug, identity, issued.Id(row.Membership));
                    using var request = IdentityPrivilegeChangeOperations.CreateProjectPrivilege(selection, new(
                        [new(row.Control == "subject" ? ProjectRoleSubject.Groups : ProjectRoleSubject.Identity,
                            row.Control == "action" ? ProjectRoleAction.Delete : ProjectRoleAction.Read)], PrivilegeLifetime.Permanent(), row.Name));
                    var result = await Send(request); if (result.IsSuccess) returned.Add((row, row.Privilege, result.Value.Id));
                }
                else if (!org && row.Action == IdentityPermissionAction.Read)
                {
                    using var request = MembershipOperations.GetProjectIdentityMembership(organization, project, identity); var result = await Send(request);
                    if (result.IsSuccess) { await Assert.That(result.Value.IdentityId).IsEqualTo(identity); returned.Add((row, row.Membership, result.Value.Id)); }
                }
                else if (!org && row.Action != IdentityPermissionAction.Edit)
                {
                    using var request = row.Action switch
                    {
                        IdentityPermissionAction.Create => MembershipOperations.AddProjectIdentity(organization, project, identity, new MembershipRoleSelection(role: "no-access")),
                        IdentityPermissionAction.AssignRole => MembershipOperations.UpdateProjectIdentityRoles(organization, project, identity, [new(role)]),
                        _ => MembershipOperations.RemoveProjectIdentity(organization, project, identity)
                    };
                    var result = await Send(request); if (result.IsSuccess) { await Assert.That(result.Value.PrincipalId).IsEqualTo(identity); returned.Add((row, row.Membership, result.Value.Id)); }
                }
                else
                {
                    using var request = !org ? IdentityOperations.UpdateProjectIdentity(organization, project, identity, name: row.Name + "-edited") : row.Action switch
                    {
                        IdentityPermissionAction.Read => IdentityOperations.GetOrganizationIdentity(organization, identity),
                        IdentityPermissionAction.Create => IdentityOperations.CreateOrganizationIdentity(organization, row.Name, "no-access"),
                        IdentityPermissionAction.Edit => IdentityOperations.UpdateOrganizationIdentity(organization, identity, name: row.Name + "-edited"),
                        IdentityPermissionAction.GrantPrivileges => IdentityOperations.UpdateOrganizationIdentity(organization, identity, role: role),
                        _ => IdentityOperations.DeleteOrganizationIdentity(organization, identity)
                    };
                    var result = await Send(request);
                    if (result.IsSuccess) { returned.Add((row, row.Identity, result.Value.Id)); await Assert.That(result.Value.Name).IsEqualTo(row.Action == IdentityPermissionAction.Edit ? row.Name + "-edited" : row.Name); }
                }
                async Task Probe(byte[] bytes)
                {
                    using var proofTokens = new MemberPermissionTokens(bytes); var proofClient = env.CreateManagementClient();
                    using var request = org ? IdentityOperations.GetOrganizationIdentity(organization, issued.Id(row.Canary)) :
                        IdentityOperations.GetProjectIdentity(organization, project, issued.Id(row.Canary));
                    var proofAuthority = new ManagementAuthority(proofClient.Authority, proofTokens, organization, request.Target.ProjectId);
                    var result = await proofClient.ExecuteAsync(request, proofAuthority, proofAuthority.IssueGrant(request.OperationId, request.Target), cancellationToken: deadline.Token);
                    await Assert.That(result.Status is SecretStatus.Success or SecretStatus.Denied).IsTrue();
                }
                async ValueTask<SecretOutcome<T>> Send<T>(ManagementRequest<T> request) where T : notnull
                {
                    var authority = new ManagementAuthority(client.Authority, tokens, organization, request.Target.ProjectId);
                    var receipt = request.IsMutation ? client.CreateReceipt(request) : null;
                    var result = await client.ExecuteAsync(request, authority, authority.IssueGrant(request.OperationId, request.Target), receipt, deadline.Token);
                    await Assert.That(result.Status).IsEqualTo(allowed ? SecretStatus.Success : SecretStatus.Denied);
                    await Assert.That(tokens.Hash).IsEqualTo(actor.CredentialHash);
                    if (receipt is not null) await Assert.That(receipt.Evidence).IsEqualTo(allowed ? DispatchEvidence.Applied : DispatchEvidence.Rejected);
                    return result;
                }
            }
            var end = after ? IdentityPermissionStep.ObserveAfter : IdentityPermissionStep.ObserveBefore;
            var packet = await source.StepAsync(root, end, null, deadline.Token); Check(packet, end);
            await Assert.That(packet.Access.Payload.Content.Decisions.Length).IsEqualTo(rows.Length);
            foreach (var row in rows.Where(r => IdentityPermissionContract.TokenAction(r.Action)))
            {
                var issue = packet.Issuer.Payload.Content.Tokens.SingleOrDefault(t => t.Row == row.Key);
                if (issue is null) continue;
                var capture = packet.Capture.Payload.Content.Single(c => c.Token == issue.Token);
                await Assert.That(capture.Hash == issue.Hash && capture.Request == issue.Request).IsTrue();
                var access = packet.TokenState.Payload.Content.Access.Where(a => a.Token == issue.Token).ToArray();
                bool invalid = packet.Access.Payload.Content.Decisions.Single(a => a.Identity == issue.Identity).Allowed &&
                    row.Action is IdentityPermissionAction.DeleteToken or IdentityPermissionAction.RevokeAuth;
                await Assert.That(access.Length).IsEqualTo(row.Action == IdentityPermissionAction.CreateToken ? 1 : 2);
                await Assert.That(access[^1].Result).IsEqualTo(invalid ? IdentityPermissionAuthentication.InvalidToken : IdentityPermissionAuthentication.Authenticated);
                await Assert.That(access[^1].HttpStatus).IsEqualTo(invalid ? 401 : 200);
                await Assert.That(access.All(a => a.Identity == issue.Identity && a.Hash == issue.Hash && a.Canary == issued!.Id(row.Canary) && a.Policy == issued.Id(row.ReadPolicy))).IsTrue();
                await Assert.That(packet.TokenState.Payload.Content.Inventory.Single(t => t.Id == issue.Token).Revoked).IsEqualTo(invalid);
            }
            foreach (var (row, key, id) in returned)
            {
                await Assert.That(issued!.Id(key)).IsEqualTo(id);
                var decision = packet.Access.Payload.Content.Decisions.Single(d => d.Identity == issued.Id(row.Identity) && d.Action == row.Action);
                await Assert.That(packet.Issuer.Payload.Content.Credentials.Any(c => c.Id == decision.CredentialId && c.Principal == decision.Actor &&
                    c.Kind == decision.Kind && c.Hash == decision.CredentialHash)).IsTrue();
                var change = packet.Storage.Payload.Content.Changes.Single(c => c.Request == decision.Request);
                await Assert.That(change.Row).IsEqualTo(row.Key);
                if (row.Action == IdentityPermissionAction.Delete) await Assert.That(change.After).IsNull();
                else await Assert.That(change.After!.Identity).IsEqualTo(issued.Id(row.Identity));
            }
        }
    }
}
