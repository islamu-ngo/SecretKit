using SecretKit.Core;
using SecretKit.Infisical.Management;
using SecretKit.TestFixtures;

namespace SecretKit.Infisical.Conformance.Tests;

// Independent direct SDK/source calibration: no Effects, Client or Trial calls.
public sealed class InfisicalAuditPermissionCalibrationTests
{
    public static IEnumerable<(string Operation, string Variant, string Boundary)> Cases() => InfisicalAuditPermissionEffectTests.Cases();
    [Test]
    [MethodDataSource(nameof(Cases))]
    public Task DirectSdkCalibratesAuditPublicationAndPermission(string operation, string variant, string boundary) => Calibrate(operation, variant, boundary);
    public static IEnumerable<(string Operation, string Boundary, int Action)> GenericCases() => InfisicalAuditPermissionEffectTests.GenericCases();
    [Test]
    [MethodDataSource(nameof(GenericCases))]
    public async Task IndependentGenericCalibrationRetainsOriginalFactory(string operation, string boundary, int action)
    {
        await Assert.That(InfisicalGovernanceFamilies.Bindings[InfisicalAuditPermissionGateTests.Execute].Variants.Contains("factory." + operation)).IsTrue();
        await Calibrate(operation, AuditPermissionContract.Variant((AuditPermissionAction)action), boundary);
    }
    private static async Task Calibrate(string operation, string variant, string boundary)
    {
        var action = InfisicalAuditPermissionGateTests.Action(variant);
        await using var provider = new InfisicalAuditPermissionFixture(); using var env = provider.Environment(operation, action);
        using var deadline = new CancellationTokenSource(TimeSpan.FromSeconds(45)); using var cap = SecretMaterial.FromText("audit-capability");
        var root = provider.Root(operation, action, boundary); var plan = new AuditPermissionPlan(root); var source = provider.Source.CreateClient();
        using var verifier = new AuditPermissionVerifier(root); var ownership = new AuditPermissionOwnership(root, plan);
        AuditPermissionIssued? issued = null;
        bool org = operation.EndsWith("OrganizationRole", StringComparison.Ordinal), template = operation.Contains("ProjectTemplate", StringComparison.Ordinal),
            privilege = operation.Contains("IdentityPrivilegeChange", StringComparison.Ordinal), create = operation.Split('.').Last().StartsWith("Create", StringComparison.Ordinal),
            applied = boundary is not ("denied-authority" or "cancellation-boundary");
        var expected = new List<AuditPermissionState>();
        var seeded = new Dictionary<string, (string Target, string Input)>();
        try
        {
            Check(await source.StepAsync(root, AuditPermissionStep.Reserve, cap, deadline.Token), AuditPermissionStep.Reserve);
            await Assert.That(provider.Generated).IsEqualTo(0);
            var opened = await source.StepAsync(root, AuditPermissionStep.Open, null, deadline.Token);
            issued = new(opened.Owner.Payload.Content.Actors, opened.Storage.Payload.Content.Bindings); Check(opened, AuditPermissionStep.Open);
            await Witness(false);
            Check(await source.StepAsync(root, AuditPermissionStep.Arm, null, deadline.Token), AuditPermissionStep.Arm);
            AuditPermissionReceipt original;
            if (org)
            {
                var change = new OrganizationRoleChange(plan.Slug, plan.Slug,
                    permissions: [new(OrganizationRoleSubject.AuditLogs, Enum.Parse<OrganizationRoleAction>(action.ToString()))]);
                original = await Original(create ? RoleChangeOperations.CreateOrganizationRole(root.Organization, change) :
                    RoleChangeOperations.UpdateOrganizationRole(root.Organization, issued.Id(plan.PolicyKey), change));
            }
            else
            {
                var selected = Enum.Parse<ProjectRoleAction>(action.ToString());
                if (template)
                {
                    var config = new ProjectTemplateConfiguration(
                        [new(plan.Slug, plan.Slug, [new(ProjectRoleSubject.AuditLogs, selected)])],
                        ProjectTemplateCollection<ProjectTemplateEnvironment>.FromValues([new("Witness", "witness", 1)]),
                        users: ProjectTemplateCollection<ProjectTemplateUser>.FromValues([new(plan.Username(plan.ActorKey(0)), [plan.Slug])]));
                    original = await Original(create ? ProjectTemplateOperations.CreateProjectTemplate(root.Organization, plan.Slug, configuration: config) :
                        ProjectTemplateOperations.UpdateProjectTemplate(root.Organization, issued.Id(plan.PolicyKey), configuration: config));
                }
                else
                {
                    ProjectRolePermission[] permissions = [new(ProjectRoleSubject.AuditLogs, selected)];
                    if (privilege)
                    {
                        await Assert.That(issued.Actors[0].Principal).IsEqualTo(InfisicalAuditPermissionFixture.Authorities.Runtime);
                        await Assert.That(issued.Actors[0].Kind).IsEqualTo(MemberPermissionActorKind.Machine);
                        var selection = new LegacyPrivilegeSelection(root.Organization, issued.Id(AuditPermissionPlan.Project), plan.ProjectSlug,
                            issued.Actors[0].Principal, issued.Id(plan.ActorMembership(0)));
                        var change = new ProjectPrivilegeChange(permissions, PrivilegeLifetime.Permanent(), plan.Slug);
                        original = await Original(create ? IdentityPrivilegeChangeOperations.CreateProjectPrivilege(selection, change) :
                            IdentityPrivilegeChangeOperations.UpdateProjectPrivilege(selection, issued.Id(plan.PolicyKey), change));
                    }
                    else
                    {
                        var change = new ProjectRoleChange(plan.Slug, plan.Slug, permissions: permissions);
                        original = await Original(create ? RoleChangeOperations.CreateProjectRole(root.Organization, issued.Id(AuditPermissionPlan.Project), change) :
                            RoleChangeOperations.UpdateProjectRole(root.Organization, issued.Id(AuditPermissionPlan.Project), issued.Id(plan.PolicyKey), change));
                    }
                }
            }
            var settled = await source.StepAsync(root, AuditPermissionStep.Settle, null, deadline.Token); Check(settled, AuditPermissionStep.Settle);
            await Assert.That(settled.Ingress.Payload.Content.Count(e => e.Phase == "original")).IsEqualTo(boundary == "cancellation-boundary" ? 0 : 1);
            await Assert.That(settled.Policy.Payload.Content.Commits.Length).IsEqualTo(applied ? 1 : 0);
            if (applied)
            {
                var persisted = settled.Policy.Payload.Content.Commits.Single();
                await Assert.That(persisted.Request).IsEqualTo(settled.Ingress.Payload.Content.Single(e => e.Phase == "original").Request);
                await Assert.That(persisted.Policy.Actor).IsEqualTo(issued.Actors[0].Principal);
                await Assert.That(persisted.Policy.Kind).IsEqualTo(privilege ? MemberPermissionActorKind.Machine : MemberPermissionActorKind.User);
                await Assert.That(persisted.Policy.Subject).IsEqualTo("audit-logs");
                await Assert.That(persisted.Policy.Actions.SequenceEqual([AuditPermissionContract.Wire(action)])).IsTrue();
                await Assert.That(persisted.Policy.Names.Length).IsEqualTo(0); await Assert.That(persisted.Policy.Role).IsEqualTo(plan.Slug);
                await Assert.That(persisted.Policy.Resource).IsEqualTo(issued.Id(plan.PolicyKey));
                await Assert.That(persisted.Policy.Organization).IsEqualTo(root.Organization);
                await Assert.That(persisted.Policy.Project).IsEqualTo(org ? "" : issued.Id(AuditPermissionPlan.Project));
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
                else _ = await Original(ProjectMembershipOperations.UpdateProjectMembershipRoles(root.Organization, issued.Id(AuditPermissionPlan.Project),
                    issued.Id(plan.ActorMembership(0)), [new(plan.Slug)]), true);
            }
            var retainedEvidence = original.Native.Evidence; await Witness(true);
            await Assert.That(original.Native.Evidence).IsEqualTo(retainedEvidence);
            await Assert.That(provider.Originals).IsEqualTo(boundary == "cancellation-boundary" ? 0 : 1);
        }
        finally
        {
            try { Check(await source.StepAsync(root, AuditPermissionStep.Close, null, CancellationToken.None), AuditPermissionStep.Close); }
            finally { issued?.Erase(); }
        }
        await InfisicalAuditPermissionEffectTests.Clean(provider);
        void Check(AuditPermissionPacket packet, AuditPermissionStep step)
        {
            verifier.Check(packet, step); ownership.Check(packet, step);
            if (issued is not null) issued = issued with { Bindings = packet.Storage.Payload.Content.Bindings };
        }
        async Task<AuditPermissionReceipt> Original<T>(ManagementRequest<T> request, bool setup = false) where T : notnull
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
            var seedStep = after ? AuditPermissionStep.SeedAfter : AuditPermissionStep.SeedBefore;
            Check(await source.StepAsync(root, seedStep, null, deadline.Token), seedStep);
            var selectedWindow = !after ? "before" : template && applied ? "copy" : "after";
            foreach (var seed in plan.Seeds.Where(s => s.Window == selectedWindow))
            {
                var client = env.CreateManagementClient();
                using var request = org ? RoleChangeOperations.CreateOrganizationRole(issued!.Id(seed.Organization),
                    new(seed.Name, seed.Slug, new("closed-seed"), [])) : RoleChangeOperations.CreateProjectRole(issued!.Id(seed.Organization), issued.Id(seed.Project),
                    new(seed.Name, seed.Slug, new("closed-seed"), []));
                var authority = env.CreateManagementAuthority(client, NativeIdentityRole.Setup, issued.Id(seed.Organization), request.Target.ProjectId);
                var receipt = client.CreateReceipt(request);
                var result = await client.ExecuteAsync(request, authority, authority.IssueGrant(request.OperationId, request.Target), receipt, deadline.Token);
                await Assert.That(result.IsSuccess).IsTrue(); await Assert.That(receipt.Evidence).IsEqualTo(DispatchEvidence.Applied);
                await Assert.That(result.Value.Permissions is { Count: 0 }).IsTrue();
                seeded.Add(seed.Key, (result.Value.Id, request.Target.SecondaryId!));
            }
            var publishStep = after ? AuditPermissionStep.PublishedAfter : AuditPermissionStep.PublishedBefore;
            var packet = await source.StepAsync(root, publishStep, null, deadline.Token); Check(packet, publishStep);
            await Assert.That(packet.Publisher.Payload.Content.ProducerFence && packet.Publisher.Payload.Content.PublicationFence).IsTrue();
            await Assert.That(packet.Publisher.Payload.Content.PendingPublications).IsEqualTo(0);
            await Assert.That(packet.Publisher.Payload.Content.Events.Length).IsEqualTo(seeded.Count);
            await Assert.That(packet.Storage.Payload.Content.Inventory.Length).IsEqualTo(seeded.Count);
            foreach (var e in packet.Publisher.Payload.Content.Events)
            {
                var entry = packet.Ingress.Payload.Content.Single(r => r.Request == e.ParentRequest);
                var commit = packet.Storage.Payload.Content.Seeds.Single(c => c.Request == entry.Request);
                var row = packet.Storage.Payload.Content.Inventory.Single(s => s.Publication == e.Event);
                var binding = packet.Issuer.Payload.Content.Bindings.Single(b => b.Intent == "audit-" + e.Seed);
                await Assert.That(entry.Actor).IsEqualTo(InfisicalAuditPermissionFixture.Authorities.Setup);
                await Assert.That(entry.Kind).IsEqualTo(MemberPermissionActorKind.Machine);
                await Assert.That(entry.IntentHash).IsEqualTo(seeded[e.Seed].Input);
                await Assert.That(entry.BodyHash).IsEqualTo(seeded[e.Seed].Input);
                await Assert.That(commit.Target).IsEqualTo(seeded[e.Seed].Target);
                await Assert.That(e.ProducerCommitHash).IsEqualTo(AuditPermissionContract.Hash(commit));
                await Assert.That(e.Actor == entry.Actor && e.CredentialHash == entry.CredentialHash && e.At == entry.At).IsTrue();
                await Assert.That(e.EventType).IsEqualTo(org ? "create-org-role" : "create-project-role");
                await Assert.That(e.EventClass).IsEqualTo(AuditEventClass.Management);
                await Assert.That(row.Id).IsEqualTo(binding.CanonicalId);
                await Assert.That(binding.Request).IsEqualTo(e.Event);
                await Assert.That(row.ParentRequest).IsEqualTo(entry.Request);
                await Assert.That(row.EventHash).IsEqualTo(AuditPermissionContract.Hash(e));
                await Assert.That(row.InputHash).IsEqualTo(seeded[e.Seed].Input);
                await Assert.That(row.Target).IsEqualTo(seeded[e.Seed].Target);
            }
            expected = packet.Storage.Payload.Content.Inventory.ToList();
            var step = after ? AuditPermissionStep.After : AuditPermissionStep.Before;
            Check(await source.StepAsync(root, step, null, deadline.Token), step);
            foreach (var row in plan.Rows.Where(r => r.Window == selectedWindow))
            {
                var actor = issued!.Actors[row.Actor];
                int offset = 0; var observed = new List<string>(); bool complete = false;
                bool allowed = after && applied && row.Control == "selected";
                for (int pageIndex = 0; pageIndex < 16; pageIndex++)
                {
                    using var tokens = actor.Owned ? new MemberPermissionTokens(actor.Credential) : new MemberPermissionTokens(env.Tokens(
                        actor.Principal == root.Authorities.Runtime ? NativeIdentityRole.Runtime : NativeIdentityRole.Denied));
                    var client = env.CreateManagementClient();
                    using var request = GovernanceOperations.ReadAudit(issued.Id(row.Organization), root.From, root.Until,
                        org ? null : issued.Id(row.Project), offset, 2, new(actor: root.Authorities.Setup, actorType: "identity",
                            eventClass: AuditEventFilter.Classes([AuditEventClass.Management]), eventType: AuditEventFilter.Types([org ? "create-org-role" : "create-project-role"])));
                    var authority = new ManagementAuthority(client.Authority, tokens, issued.Id(row.Organization), request.Target.ProjectId);
                    var result = await client.ExecuteAsync(request, authority, authority.IssueGrant(request.OperationId, request.Target), cancellationToken: deadline.Token);
                    await Assert.That(tokens.Hash).IsEqualTo(actor.CredentialHash);
                    await Assert.That(result.Status).IsEqualTo(allowed ? SecretStatus.Success : SecretStatus.Denied);
                    if (!allowed) { complete = true; break; }
                    await Assert.That(result.Value.Items.Select(r => r.Ordinal).SequenceEqual(Enumerable.Range(offset, result.Value.Items.Count))).IsTrue();
                    foreach (var item in result.Value.Items)
                    {
                        await Assert.That(item.Outcome.IsSuccess).IsTrue(); var v = item.Outcome.Value;
                        await Assert.That(v.IncludesActorMetadata || v.IncludesEventMetadata).IsFalse();
                        var canonical = expected.Single(s => s.Id == v.Id);
                        await Assert.That(v.ProjectId ?? "").IsEqualTo(canonical.Project);
                        await Assert.That(v.EventClass).IsEqualTo(AuditEventClass.Management);
                        await Assert.That(v.EventType).IsEqualTo(org ? "create-org-role" : "create-project-role");
                        await Assert.That(v.ActorType).IsEqualTo("identity"); observed.Add(v.Id);
                    }
                    if (result.Value.IsComplete) { complete = true; break; }
                    await Assert.That(result.Value.NextOffset).IsEqualTo(offset + 2); offset += 2;
                }
                await Assert.That(complete).IsTrue();
                var selected = allowed ? expected.Where(s => s.Organization == issued.Id(row.Organization) && (org || s.Project == issued.Id(row.Project))).Select(s => s.Id).ToArray() : [];
                await Assert.That(observed.Count == selected.Length && observed.Distinct().Count() == selected.Length &&
                    observed.ToHashSet().SetEquals(selected)).IsTrue();
            }
            var observe = after ? AuditPermissionStep.ObserveAfter : AuditPermissionStep.ObserveBefore;
            var observedPacket = await source.StepAsync(root, observe, null, deadline.Token); Check(observedPacket, observe);
            await Assert.That(observedPacket.Storage.Payload.Content.Inventory.SequenceEqual(expected)).IsTrue();
        }
    }
}
