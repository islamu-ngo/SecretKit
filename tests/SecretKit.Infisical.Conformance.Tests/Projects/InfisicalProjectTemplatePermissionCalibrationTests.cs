using System.Text.Json;
using SecretKit.Core;
using SecretKit.Infisical.Management;
using SecretKit.TestFixtures;

namespace SecretKit.Infisical.Conformance.Tests;

// Independent direct SDK calibration. No Effects, Client, Trial, NativeConfiguration
// or Snapshot call is used. Constructor inputs and projected full configuration are
// independently authored; source journals must correlate authenticated requests.
public sealed class InfisicalProjectTemplatePermissionCalibrationTests
{
    public static IEnumerable<(string Operation, string Variant, string Boundary)> Cases() => InfisicalProjectTemplatePermissionGateTests.Cases();
    [Test]
    [MethodDataSource(nameof(Cases))]
    public async Task DirectSdkCalibratesOrgRoleGrantAndCompleteTemplateCrud(string operation, string variant, string boundary)
    {
        var action = InfisicalProjectTemplatePermissionGateTests.Action(variant);
        await using var provider = new InfisicalProjectTemplatePermissionFixture(); using var env = provider.Environment(operation, action);
        using var deadline = new CancellationTokenSource(TimeSpan.FromSeconds(45)); using var cap = SecretMaterial.FromText("project-template-capability");
        var root = provider.Root(operation, action, boundary); var plan = new ProjectTemplatePermissionPlan(root); var source = provider.Source.CreateClient();
        using var verifier = new ProjectTemplatePermissionVerifier(root); var ownership = new ProjectTemplatePermissionOwnership(root, plan);
        ProjectTemplatePermissionIssued? issued = null;
        bool create = operation.EndsWith(".CreateOrganizationRole", StringComparison.Ordinal), applied = boundary is not ("denied-authority" or "cancellation-boundary");
        var expected = new Dictionary<string, ProjectTemplatePermissionState>();
        try
        {
            Check(await source.StepAsync(root, ProjectTemplatePermissionStep.Reserve, cap, deadline.Token), ProjectTemplatePermissionStep.Reserve);
            await Assert.That(provider.Generated).IsEqualTo(0);
            var opened = await source.StepAsync(root, ProjectTemplatePermissionStep.Open, null, deadline.Token);
            issued = new(opened.Owner.Payload.Content.Actors, opened.Storage.Payload.Content.Bindings); Check(opened, ProjectTemplatePermissionStep.Open);
            for (int i = 0; i < 2; i++)
            {
                await Assert.That(issued.Actors[i].Kind).IsEqualTo(MemberPermissionActorKind.User);
                await Assert.That(issued.Actors[i].Owned).IsTrue();
                await Assert.That(opened.Membership.Payload.Content.Any(j => j.Principal == issued.Actors[i].Principal && j.Kind == "user" && j.Organization == root.Organization &&
                    j.Membership == issued.Id(plan.ActorMembership(i)))).IsTrue();
            }
            foreach (var row in plan.Rows.Where(r => r.Action != ProjectTemplatePermissionAction.Create)) expected.Add(row.Key,
                new(row.Key, issued.Id(row.Template), issued.Id(row.Organization), row.Name, "closed-v1", "secret-manager", ExpectedConfiguration(1), 1));
            await Assert.That(opened.Storage.Payload.Content.Inventory.OrderBy(s => s.Row).SequenceEqual(expected.Values.OrderBy(s => s.Row))).IsTrue();
            await Witness(false);
            Check(await source.StepAsync(root, ProjectTemplatePermissionStep.Arm, null, deadline.Token), ProjectTemplatePermissionStep.Arm);
            var change = new OrganizationRoleChange(plan.Slug, plan.Slug,
                permissions: [new(OrganizationRoleSubject.ProjectTemplates, Enum.Parse<OrganizationRoleAction>(action.ToString()))]);
            var original = await Original(create ? RoleChangeOperations.CreateOrganizationRole(root.Organization, change) :
                RoleChangeOperations.UpdateOrganizationRole(root.Organization, issued.Id(ProjectTemplatePermissionPlan.Policy), change));
            var settled = await source.StepAsync(root, ProjectTemplatePermissionStep.Settle, null, deadline.Token); Check(settled, ProjectTemplatePermissionStep.Settle);
            await Assert.That(settled.Ingress.Payload.Content.Length).IsEqualTo(boundary == "cancellation-boundary" ? 0 : 1);
            await Assert.That(settled.Policy.Payload.Content.Commits.Length).IsEqualTo(applied ? 1 : 0);
            if (applied)
            {
                var commit = settled.Policy.Payload.Content.Commits.Single(); var p = commit.Policy;
                await Assert.That(commit.Request).IsEqualTo(settled.Ingress.Payload.Content.Single().Request);
                await Assert.That(p.Actor).IsEqualTo(issued.Actors[0].Principal); await Assert.That(p.Kind).IsEqualTo(MemberPermissionActorKind.User);
                await Assert.That(p.Organization).IsEqualTo(root.Organization); await Assert.That(p.Project).IsEqualTo("");
                await Assert.That(p.Subject).IsEqualTo("project-templates"); await Assert.That(p.Actions.SequenceEqual([action.ToString().ToLowerInvariant()])).IsTrue();
                await Assert.That(p.Role).IsEqualTo(plan.Slug); await Assert.That(p.Names.Length).IsEqualTo(0);
            }
            var evidence = boundary switch
            {
                "denied-authority" => DispatchEvidence.Rejected,
                "cancellation-boundary" => DispatchEvidence.NotDispatched,
                "lost-response-no-replay" => DispatchEvidence.PossiblyDispatched,
                _ => DispatchEvidence.Applied
            };
            await Assert.That(original.Native.Evidence).IsEqualTo(evidence);
            if (applied && create) _ = await Original(OrganizationMembershipOperations.UpdateOrganizationMembership(root.Organization,
                issued.Id(plan.ActorMembership(0)), role: plan.Slug), true);
            await Witness(true);
            await Assert.That(original.Native.Evidence).IsEqualTo(evidence); await Assert.That(provider.Originals).IsEqualTo(boundary == "cancellation-boundary" ? 0 : 1);
        }
        finally
        {
            try { Check(await source.StepAsync(root, ProjectTemplatePermissionStep.Close, null, CancellationToken.None), ProjectTemplatePermissionStep.Close); }
            finally { issued?.Erase(); }
        }
        await InfisicalProjectTemplatePermissionEffectTests.Clean(provider);
        void Check(ProjectTemplatePermissionPacket packet, ProjectTemplatePermissionStep step)
        {
            verifier.Check(packet, step); ownership.Check(packet, step);
            if (issued is not null) issued = issued with { Bindings = packet.Storage.Payload.Content.Bindings };
        }
        string ExpectedConfiguration(int v) => JsonSerializer.Serialize(new
        {
            roles = new[] { new { name = "Closed " + v, slug = "closed-" + root.Nonce[..8] + "-" + v, permissions = Array.Empty<object>() } },
            environments = new[] { new { name = "Canary " + v, slug = "canary-" + v, position = (double)v } },
            users = Array.Empty<object>(),
            groups = Array.Empty<object>(),
            identities = Array.Empty<object>(),
            projectManagedIdentities = Array.Empty<object>()
        });
        ProjectTemplateConfiguration Configuration(int v) => new([new("Closed " + v, "closed-" + root.Nonce[..8] + "-" + v, [])],
            ProjectTemplateCollection<ProjectTemplateEnvironment>.FromValues([new("Canary " + v, "canary-" + v, v)]),
            ProjectTemplateCollection<ProjectTemplateUser>.FromValues([]), ProjectTemplateCollection<ProjectTemplateGroup>.FromValues([]),
            ProjectTemplateCollection<ProjectTemplateIdentity>.FromValues([]), ProjectTemplateCollection<ProjectTemplateManagedIdentity>.FromValues([]));
        async Task<ProjectTemplatePermissionReceipt> Original<T>(ManagementRequest<T> request, bool setup = false) where T : notnull
        {
            using (request)
            {
                var client = env.CreateManagementClient(); var receipt = client.CreateReceipt(request);
                var identity = setup ? NativeIdentityRole.Setup : boundary == "denied-authority" ? NativeIdentityRole.Denied : NativeIdentityRole.Administrative;
                var barrier = !setup && boundary == "cancellation-boundary" ? new ProjectTokenBarrier(env.Tokens(identity)) : null;
                using var cancellation = CancellationTokenSource.CreateLinkedTokenSource(deadline.Token);
                using var loss = !setup && boundary == "lost-response-no-replay" ? new ProjectResponseBoundary(env.Origin, cancellation) : null;
                using var scope = loss?.Enter(); Task? signal = barrier?.Entered;
                var authority = new ManagementAuthority(client.Authority, barrier ?? env.Tokens(identity), root.Organization);
                var execution = client.ExecuteAsync(request, authority, authority.IssueGrant(request.OperationId, request.Target), receipt, cancellation.Token).AsTask();
                SecretOutcome<T>? result = null; bool cancelled = false;
                try
                {
                    if (signal is not null) { await signal.WaitAsync(deadline.Token); cancellation.Cancel(); barrier!.Release(); }
                    try { result = await execution; } catch (OperationCanceledException) when (cancellation.IsCancellationRequested && !deadline.IsCancellationRequested) { cancelled = true; }
                    await Assert.That(loss is null || loss.Reached).IsTrue();
                    if (setup) await Assert.That(result is { IsSuccess: true }).IsTrue();
                    return new(receipt, result?.Status, cancelled, request.Target.SecondaryId ?? "");
                }
                finally
                {
                    cancellation.Cancel(); barrier?.Release(); try { result ??= await execution; } catch (OperationCanceledException) { }
                    if (result is { IsSuccess: true } completed && completed.Value is IDisposable owned) owned.Dispose();
                }
            }
        }
        async Task Witness(bool after)
        {
            var start = after ? ProjectTemplatePermissionStep.After : ProjectTemplatePermissionStep.Before;
            Check(await source.StepAsync(root, start, null, deadline.Token), start);
            var rows = plan.Rows.Where(r => r.Window == (after ? "after" : "before")).ToArray();
            var returned = new Dictionary<string, ProjectTemplateSummary>();
            var submitted = new Dictionary<string, string>();
            foreach (var row in rows)
            {
                var actor = issued!.Actors[row.Actor]; string org = issued.Id(row.Organization), id = issued.Id(row.Template);
                using var tokens = actor.Owned ? new MemberPermissionTokens(actor.Credential) : new MemberPermissionTokens(env.Tokens(NativeIdentityRole.Runtime));
                var client = env.CreateManagementClient(); using var request = row.Action switch
                {
                    ProjectTemplatePermissionAction.Read => ProjectTemplateOperations.GetProjectTemplate(org, id),
                    ProjectTemplatePermissionAction.Create => ProjectTemplateOperations.CreateProjectTemplate(org, row.Name, ProjectTemplateType.SecretManager, "closed-v1", Configuration(1)),
                    ProjectTemplatePermissionAction.Edit => ProjectTemplateOperations.UpdateProjectTemplate(org, id, row.Name + "-edited", "closed-v2", Configuration(2)),
                    _ => ProjectTemplateOperations.DeleteProjectTemplate(org, id)
                };
                var authority = new ManagementAuthority(client.Authority, tokens, org); var receipt = request.IsMutation ? client.CreateReceipt(request) : null;
                submitted.Add(row.Key, request.Target.SecondaryId ?? ProjectTemplatePermissionContract.RawHash([]));
                var response = await client.ExecuteAsync(request, authority, authority.IssueGrant(request.OperationId, request.Target), receipt, deadline.Token);
                bool allow = row.Control == "selected" && (after && applied ? row.Action == action : !create && (int)row.Action == ((int)action + 1) % 4);
                await Assert.That(response.Status).IsEqualTo(allow ? SecretStatus.Success : SecretStatus.Denied);
                await Assert.That(tokens.Hash).IsEqualTo(actor.CredentialHash);
                if (receipt is not null) await Assert.That(receipt.Evidence).IsEqualTo(allow ? DispatchEvidence.Applied : DispatchEvidence.Rejected);
                if (allow) returned.Add(row.Key, response.Value);
            }
            var end = after ? ProjectTemplatePermissionStep.ObserveAfter : ProjectTemplatePermissionStep.ObserveBefore;
            var packet = await source.StepAsync(root, end, null, deadline.Token); Check(packet, end);
            var binding = packet.Membership.Payload.Content.Single(j => j.Membership == issued!.Id(plan.ActorMembership(0)));
            bool assigned = !create || after && applied;
            await Assert.That(binding.RoleId).IsEqualTo(assigned ? issued!.Id(plan.PolicyKey) : "");
            await Assert.That(binding.RoleSlug).IsEqualTo(assigned ? plan.Slug : "no-access");
            await Assert.That(binding.Active && binding.Status == "accepted" && binding.Kind == "user" && binding.Assigned == assigned).IsTrue();
            await Assert.That(packet.Access.Payload.Content.Length).IsEqualTo(rows.Length);
            for (int index = 0; index < rows.Length; index++)
            {
                var row = rows[index]; var decision = packet.Access.Payload.Content[index]; var actor = issued!.Actors[row.Actor];
                await Assert.That(decision.Template).IsEqualTo(issued.Id(row.Template)); await Assert.That(decision.Action).IsEqualTo(row.Action);
                await Assert.That(decision.Actor).IsEqualTo(actor.Principal); await Assert.That(decision.Kind).IsEqualTo(actor.Kind);
                await Assert.That(decision.CredentialHash).IsEqualTo(actor.CredentialHash); await Assert.That(decision.Organization).IsEqualTo(issued.Id(row.Organization));
                var ingress = packet.Ingress.Payload.Content.Single(e => e.Request == decision.Request);
                await Assert.That(ingress.BodyHash).IsEqualTo(submitted[row.Key]); await Assert.That(ingress.CredentialHash).IsEqualTo(actor.CredentialHash);
                await Assert.That(ingress.Path).IsEqualTo("/api/v1/project-templates" +
                    (row.Action == ProjectTemplatePermissionAction.Create ? "" : "/" + issued.Id(row.Template)));
                await Assert.That(packet.Issuer.Payload.Content.Credentials.Any(c => c.Id == decision.CredentialId && c.Principal == decision.Actor && c.Kind == decision.Kind && c.Hash == decision.CredentialHash)).IsTrue();
                var before = expected.GetValueOrDefault(row.Key); var next = before;
                if (returned.TryGetValue(row.Key, out var value))
                {
                    int version = row.Action == ProjectTemplatePermissionAction.Edit ? 2 : 1;
                    var projected = new ProjectTemplatePermissionState(row.Key, value.Id, value.OrganizationId, value.Name, value.Description!, value.Type!, JsonSerializer.Serialize(new
                    {
                        roles = value.Roles.Select(r => new { name = r.Name, slug = r.Slug, permissions = Array.Empty<object>() }).ToArray(),
                        environments = value.Environments!.Select(e => new { name = e.Name, slug = e.Slug, position = e.Position }).ToArray(),
                        users = Array.Empty<object>(),
                        groups = Array.Empty<object>(),
                        identities = Array.Empty<object>(),
                        projectManagedIdentities = Array.Empty<object>()
                    }), version);
                    await Assert.That(value.Roles.All(r => r.Permissions.Count == 0)).IsTrue();
                    await Assert.That(value.Users is { Count: 0 } && value.Groups is { Count: 0 } && value.Identities is { Count: 0 } && value.ProjectManagedIdentities is { Count: 0 }).IsTrue();
                    var full = new ProjectTemplatePermissionState(row.Key, issued!.Id(row.Template), issued.Id(row.Organization),
                        row.Action == ProjectTemplatePermissionAction.Edit ? row.Name + "-edited" : row.Name, "closed-v" + version, "secret-manager", ExpectedConfiguration(version), version);
                    await Assert.That(projected).IsEqualTo(full);
                    next = row.Action == ProjectTemplatePermissionAction.Delete ? null : full;
                }
                var change = packet.Storage.Payload.Content.Changes.Single(c => c.Request == decision.Request);
                await Assert.That(change).IsEqualTo(new ProjectTemplatePermissionChange(decision.Request, row.Key, before, next));
                if (next is null) expected.Remove(row.Key); else expected[row.Key] = next;
            }
            await Assert.That(packet.Storage.Payload.Content.Inventory.OrderBy(s => s.Row).SequenceEqual(expected.Values.OrderBy(s => s.Row))).IsTrue();
            // Fresh typed observer inventory reads independently persisted bytes,
            // not the original create/update response or its nullable omissions.
            var observer = env.CreateManagementClient(); using var list = ProjectTemplateOperations.ListProjectTemplates(root.Organization, ProjectTemplateType.SecretManager);
            var auditAuthority = new ManagementAuthority(observer.Authority, env.Tokens(NativeIdentityRole.Observer), root.Organization);
            var inventory = await observer.ExecuteAsync(list, auditAuthority, auditAuthority.IssueGrant(list.OperationId, list.Target), cancellationToken: deadline.Token);
            await Assert.That(inventory.IsSuccess).IsTrue();
            await Assert.That(inventory.Value.Items.Select(t => t.Id).Order().SequenceEqual(expected.Values.Where(s => s.Organization == root.Organization).Select(s => s.Template).Order())).IsTrue();
            foreach (var template in inventory.Value.Items)
            {
                var stored = expected.Values.Single(s => s.Template == template.Id);
                await Assert.That(template.Name).IsEqualTo(stored.Name); await Assert.That(template.Description).IsEqualTo(stored.Description); await Assert.That(template.Type).IsEqualTo(stored.Type);
                await Assert.That(template.Roles.Single().Slug).IsEqualTo("closed-" + root.Nonce[..8] + "-" + stored.Version);
                await Assert.That(template.Environments!.Single().Position).IsEqualTo((double)stored.Version);
                await Assert.That(template.Users is { Count: 0 } && template.Groups is { Count: 0 } && template.Identities is { Count: 0 } && template.ProjectManagedIdentities is { Count: 0 }).IsTrue();
                await Assert.That(template.Roles.All(r => r.Permissions.Count == 0)).IsTrue();
                if (template.Environments is not { } environments) throw new NativeCaseFailureException("effect-mismatch");
                string configuration = JsonSerializer.Serialize(new
                {
                    roles = template.Roles.Select(r => new { name = r.Name, slug = r.Slug, permissions = Array.Empty<object>() }).ToArray(),
                    environments = environments.Select(e => new { name = e.Name, slug = e.Slug, position = e.Position }).ToArray(),
                    users = Array.Empty<object>(),
                    groups = Array.Empty<object>(),
                    identities = Array.Empty<object>(),
                    projectManagedIdentities = Array.Empty<object>()
                });
                await Assert.That(configuration).IsEqualTo(stored.Configuration);
            }
        }
    }
}
