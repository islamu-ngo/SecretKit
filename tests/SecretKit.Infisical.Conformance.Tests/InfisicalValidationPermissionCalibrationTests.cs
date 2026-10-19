using System.Security.Cryptography;
using System.Text.Json;
using SecretKit.Core;
using SecretKit.Infisical.Management;
using SecretKit.TestFixtures;

namespace SecretKit.Infisical.Conformance.Tests;

// Direct public SDK and source calibration. No Effects, Client, or Trial helper calls.
public sealed class InfisicalValidationPermissionCalibrationTests
{
    public static IEnumerable<(string Operation, string Variant, string Boundary)> Cases() => InfisicalValidationPermissionOriginalTests.Cases();
    public static IEnumerable<(string Operation, string Boundary, int Action)> GenericCases() => InfisicalValidationPermissionOriginalTests.GenericCases();
    [Test]
    [MethodDataSource(nameof(Cases))]
    public Task DirectSdkCalibratesGrantRuleEnforcementAndCommittedState(string operation, string variant, string boundary) => Calibrate(operation, InfisicalValidationPermissionGateTests.Action(variant), boundary);
    [Test]
    [MethodDataSource(nameof(GenericCases))]
    public Task DirectGenericCalibrationPreservesFactoryAndConfiguredAction(string operation, string boundary, int action) => Calibrate(operation, (ValidationPermissionAction)action, boundary);
    private static async Task Calibrate(string operation, ValidationPermissionAction action, string boundary)
    {
        await using var provider = new InfisicalValidationPermissionFixture(); using var env = provider.Environment(operation, action);
        using var deadline = new CancellationTokenSource(TimeSpan.FromSeconds(60)); using var cap = SecretMaterial.FromText("validation-capability");
        var root = provider.Root(operation, action, boundary); var plan = new ValidationPermissionPlan(root); var source = provider.Source.CreateClient();
        using var verifier = new ValidationPermissionVerifier(root); var ownership = new ValidationPermissionOwnership(root, plan); var causal = new ValidationPermissionCausality(); var history = new ValidationPermissionHistory();
        ValidationPermissionIssued? issued = null; var states = new Dictionary<string, ValidationPermissionState>();
        bool template = operation.Contains("ProjectTemplate", StringComparison.Ordinal), privilege = operation.Contains("IdentityPrivilegeChange", StringComparison.Ordinal),
            create = operation.Split('.').Last().StartsWith("Create", StringComparison.Ordinal), applied = boundary is not ("denied-authority" or "cancellation-boundary");
        try
        {
            Check(await source.StepAsync(root, ValidationPermissionStep.Reserve, cap, deadline.Token), ValidationPermissionStep.Reserve);
            await Assert.That(provider.Generated).IsEqualTo(0);
            var opened = await source.StepAsync(root, ValidationPermissionStep.Open, null, deadline.Token);
            issued = new(opened.Owner.Payload.Content.Actors, opened.Storage.Payload.Content.Bindings); Check(opened, ValidationPermissionStep.Open);
            await Assert.That(issued.Actors[0].Kind).IsEqualTo(privilege ? MemberPermissionActorKind.Machine : MemberPermissionActorKind.User);
            if (privilege) await Assert.That(issued.Actors[0].Principal).IsEqualTo(root.Authorities.Runtime);
            await Assert.That(issued.Actors[3].Kind).IsEqualTo(MemberPermissionActorKind.Machine);
            await Assert.That(issued.Actors[3].Principal == issued.Actors[0].Principal).IsFalse();
            foreach (var row in plan.Rows.Where(r => r.Window != "copy" && r.Action != ValidationPermissionAction.Create)) states.Add(row.Key, plan.Initial(row, issued));
            causal.Open(opened, plan, issued); await Witness(false);
            Check(await source.StepAsync(root, ValidationPermissionStep.Arm, null, deadline.Token), ValidationPermissionStep.Arm);
            var selected = Enum.Parse<ProjectRoleAction>(action.ToString()); ValidationPermissionReceipt original;
            if (template)
            {
                var config = new ProjectTemplateConfiguration([new(plan.Slug, plan.Slug, [new(ProjectRoleSubject.SecretValidationRules, selected)])],
                    ProjectTemplateCollection<ProjectTemplateEnvironment>.FromValues([new("Development", "dev", 1.5)]),
                    users: ProjectTemplateCollection<ProjectTemplateUser>.FromValues([new(plan.Username(plan.ActorKey(0)), [plan.Slug])]));
                original = await Send(create ? ProjectTemplateOperations.CreateProjectTemplate(root.Organization, plan.Slug, configuration: config) :
                    ProjectTemplateOperations.UpdateProjectTemplate(root.Organization, issued.Id(plan.PolicyKey), configuration: config));
            }
            else if (privilege)
            {
                var selection = new LegacyPrivilegeSelection(root.Organization, issued.Id(ValidationPermissionPlan.Project), plan.ProjectSlug, issued.Actors[0].Principal, issued.Id(plan.ActorMembership(0)));
                var change = new ProjectPrivilegeChange([new(ProjectRoleSubject.SecretValidationRules, selected)], PrivilegeLifetime.Permanent(), plan.Slug);
                original = await Send(create ? IdentityPrivilegeChangeOperations.CreateProjectPrivilege(selection, change) : IdentityPrivilegeChangeOperations.UpdateProjectPrivilege(selection, issued.Id(plan.PolicyKey), change));
            }
            else
            {
                var change = new ProjectRoleChange(plan.Slug, plan.Slug, permissions: [new(ProjectRoleSubject.SecretValidationRules, selected)]);
                original = await Send(create ? RoleChangeOperations.CreateProjectRole(root.Organization, issued.Id(ValidationPermissionPlan.Project), change) :
                    RoleChangeOperations.UpdateProjectRole(root.Organization, issued.Id(ValidationPermissionPlan.Project), issued.Id(plan.PolicyKey), change));
            }
            var settled = await source.StepAsync(root, ValidationPermissionStep.Settle, null, deadline.Token); Check(settled, ValidationPermissionStep.Settle);
            await Assert.That(settled.Ingress.Payload.Content.Events.Length).IsEqualTo(boundary == "cancellation-boundary" ? 0 : 1);
            await Assert.That(settled.Policy.Payload.Content.Commits.Length).IsEqualTo(applied ? 1 : 0);
            if (applied)
            {
                var commit = settled.Policy.Payload.Content.Commits.Single(); var entry = settled.Ingress.Payload.Content.Events.Single();
                await Assert.That(commit.Request).IsEqualTo(entry.Request); await Assert.That(commit.Policy.Configuration).IsEqualTo(entry.BodyHash);
                await Assert.That(commit.Policy.Actor).IsEqualTo(issued.Actors[0].Principal); await Assert.That(commit.Policy.Resource).IsEqualTo(issued.Id(plan.PolicyKey));
                await Assert.That(commit.Policy.Subject).IsEqualTo("secret-validation-rules"); await Assert.That(commit.Policy.Actions.SequenceEqual([action.ToString().ToLowerInvariant()])).IsTrue();
                await Assert.That(commit.Policy.Names.Length).IsEqualTo(0);
            }
            var retained = original.Native.Evidence;
            await Assert.That(retained).IsEqualTo(boundary switch
            {
                "denied-authority" => DispatchEvidence.Rejected,
                "cancellation-boundary" => DispatchEvidence.NotDispatched,
                "lost-response-no-replay" => DispatchEvidence.PossiblyDispatched,
                _ => DispatchEvidence.Applied
            });
            if (applied && template) _ = await Send(ProjectOperations.CreateProject(root.Organization, plan.CopySlug, plan.CopySlug, template: plan.Slug, createDefaultEnvironments: false), true);
            else if (applied && create && !privilege) _ = await Send(ProjectMembershipOperations.UpdateProjectMembershipRoles(root.Organization, issued.Id(ValidationPermissionPlan.Project), issued.Id(plan.ActorMembership(0)), [new(plan.Slug)]), true);
            await Witness(true); await Assert.That(original.Native.Evidence).IsEqualTo(retained);
            await Assert.That(provider.Originals).IsEqualTo(boundary == "cancellation-boundary" ? 0 : 1);
        }
        finally
        {
            try { var close = await source.StepAsync(root, ValidationPermissionStep.Close, null, CancellationToken.None); Check(close, ValidationPermissionStep.Close); causal.Close(close); }
            finally { issued?.Erase(); }
        }
        await InfisicalValidationPermissionEffectTests.Clean(provider);
        void Check(ValidationPermissionPacket p, ValidationPermissionStep step)
        {
            verifier.Check(p, step); ownership.Check(p, step); history.Check(p, step); if (issued is not null) issued = issued with { Bindings = p.Storage.Payload.Content.Bindings };
        }
        async Task Witness(bool after)
        {
            var begin = after ? ValidationPermissionStep.After : ValidationPermissionStep.Before;
            var initial = await source.StepAsync(root, begin, null, deadline.Token); Check(initial, begin);
            if (after && template && applied)
            {
                foreach (var row in plan.Rows.Where(r => r.Window == "copy" && r.Action != ValidationPermissionAction.Create)) states.Add(row.Key, plan.Initial(row, issued!));
                causal.CopySeeds(initial, plan, issued!);
            }
            var rows = plan.Rows.Where(r => r.Window == (!after ? "before" : template && applied ? "copy" : "after")).ToArray();
            var actions = new List<(ValidationPermissionRow Row, ValidationPermissionWriteAttempt[] Before, ValidationPermissionWriteAttempt[] After, bool Allowed, InfisicalValidationRule? Rule)>();
            foreach (var row in rows)
            {
                var pre = await Writes(row, false); var actor = issued!.Actors[row.Actor];
                using var tokens = actor.Owned ? new MemberPermissionTokens(actor.Credential) : new MemberPermissionTokens(env.Tokens(actor.Principal == root.Authorities.Runtime ? NativeIdentityRole.Runtime : NativeIdentityRole.Denied));
                await using var client = new InfisicalClient(env.Origin, tokens, new InfisicalNetworkOptions { AllowLoopbackDevelopmentHttp = true });
                string project = issued.Id(row.Project);
                var target = new SecretReference(client.Authority, new InfisicalValidationAddress(project, InfisicalValidationKind.StaticSecrets, row.Action == ValidationPermissionAction.Create ? null : issued.Id(row.Target), "dev", row.Slug));
                var auth = new InfisicalNativeAuthority(client.Authority, tokens, project); var receipt = new MutationReceipt(target);
                bool edit = row.Action == ValidationPermissionAction.Edit;
                var input = new InfisicalValidationInput(row.Name + (edit ? "-v2" : ""), edit ? "changed constraint" : "closed constraint", !edit,
                    new(5, 80, "^KEY_[A-Z0-9_]+_X$", "KEY_", "_X"), new(8, 40, edit ? "^NEXT_[A-Z0-9_]+_OK$" : "^PASS_[A-Z0-9_]+_OK$", edit ? "NEXT_" : "PASS_", "_OK"), environment: "dev", secretPath: row.Slug);
                var result = row.Action switch
                {
                    ValidationPermissionAction.Read => await client.GetValidationRuleAsync(target, deadline.Token),
                    ValidationPermissionAction.Create => await client.CreateValidationRuleAsync(target, input, auth, receipt, deadline.Token),
                    ValidationPermissionAction.Edit => await client.UpdateValidationRuleAsync(target, input, auth, receipt, deadline.Token),
                    _ => await client.DeleteValidationRuleAsync(target, auth, receipt, deadline.Token)
                };
                bool allowed = row.Control == "selected" && (after && applied ? row.Action == action : !create && (int)row.Action == ((int)action + 1) % 4);
                await Assert.That(result.Status).IsEqualTo(allowed ? SecretStatus.Success : SecretStatus.Denied);
                if (row.Action != ValidationPermissionAction.Read) await Assert.That(receipt.Evidence).IsEqualTo(allowed ? DispatchEvidence.Applied : DispatchEvidence.Rejected);
                var post = await Writes(row, true); actions.Add((row, pre, post, allowed, result.IsSuccess ? result.Value : null));
            }
            var end = after ? ValidationPermissionStep.ObserveAfter : ValidationPermissionStep.ObserveBefore;
            var packet = await source.StepAsync(root, end, null, deadline.Token); Check(packet, end);
            await Assert.That(packet.Access.Payload.Content.Rules.Length).IsEqualTo(rows.Length);
            foreach (var a in actions)
            {
                causal.Observe(packet, issued!, a.Row, states.Values, a.Before, false);
                var old = states.GetValueOrDefault(a.Row.Key); var next = old;
                if (a.Allowed)
                {
                    var expected = a.Row.Action == ValidationPermissionAction.Edit ? ValidationPermissionPlan.Configuration(a.Row, old!.Target, old.Organization, old.Project, true) : plan.Initial(a.Row, issued!);
                    await Assert.That(ValidationPermissionPlan.Snapshot(a.Row, root.Organization, a.Rule!, expected.Version)).IsEqualTo(expected);
                    next = a.Row.Action == ValidationPermissionAction.Delete ? null : expected;
                }
                var mutation = packet.Storage.Payload.Content.Changes.Single(c => c.Row == a.Row.Key);
                var decision = packet.Access.Payload.Content.Rules.Single(d => d.Request == mutation.Request);
                await Assert.That(decision.Target == issued!.Id(a.Row.Target) && decision.Action == a.Row.Action && decision.Actor == issued.Actors[a.Row.Actor].Principal).IsTrue();
                await Assert.That(packet.Storage.Payload.Content.Changes.Single(c => c.Request == decision.Request)).IsEqualTo(new ValidationPermissionChange(decision.Request, a.Row.Key, old, next));
                if (next is null) states.Remove(a.Row.Key); else states[a.Row.Key] = next;
                causal.Observe(packet, issued!, a.Row, states.Values, a.After, true);
            }
            causal.Complete(packet, rows.Length * 16);
            await Assert.That(packet.Storage.Payload.Content.Inventory.OrderBy(s => s.Row).SequenceEqual(states.Values.OrderBy(s => s.Row))).IsTrue();
            await using var observer = env.CreateObserverClient();
            foreach (var project in new[] { ValidationPermissionPlan.Project, ValidationPermissionPlan.OtherProject, ValidationPermissionPlan.CopyProject }.Select(issued!.Id).Where(p => p.Length > 0))
            {
                var list = await observer.ListValidationRulesAsync(new(observer.Authority, new InfisicalValidationAddress(project, InfisicalValidationKind.StaticSecrets)), cancellationToken: deadline.Token);
                await Assert.That(list.IsSuccess && list.Value.IsComplete).IsTrue();
                await Assert.That(list.Value.Items.Select(r => r.Id).Order().SequenceEqual(states.Values.Where(s => s.Project == project).Select(s => s.Target).Order())).IsTrue();
                foreach (var rule in list.Value.Items)
                {
                    var state = states.Values.Single(s => s.Target == rule.Id); var row = plan.Rows.Single(r => r.Key == state.Row);
                    var read = await observer.GetValidationRuleAsync(new(observer.Authority, new InfisicalValidationAddress(project, InfisicalValidationKind.StaticSecrets, rule.Id, rule.Environment, rule.SecretPath)), deadline.Token);
                    await Assert.That(read.IsSuccess && ValidationPermissionPlan.Snapshot(row, root.Organization, read.Value, state.Version) == state).IsTrue();
                }
            }
        }
        async Task<ValidationPermissionWriteAttempt[]> Writes(ValidationPermissionRow row, bool after)
        {
            var result = new List<ValidationPermissionWriteAttempt>(); await using var observer = env.CreateObserverClient();
            foreach (var p in ValidationPermissionPlan.Probes(row, after))
            {
                var actor = issued!.Actors[p.Actor]; using var tokens = actor.Owned ? new MemberPermissionTokens(actor.Credential) : new MemberPermissionTokens(env.Tokens(NativeIdentityRole.Runtime));
                await using var c = new InfisicalClient(env.Origin, tokens, new InfisicalNetworkOptions { AllowLoopbackDevelopmentHttp = true });
                string project = issued.Id(row.Project); var address = new InfisicalSecretAddress(project, p.Environment, p.Path, p.Name); var target = new SecretReference(c.Authority, address);
                var receipt = new MutationReceipt(target); using var value = SecretMaterial.FromText(p.Value);
                byte[] bytes = JsonSerializer.SerializeToUtf8Bytes(new { projectId = project, environment = p.Environment, secretPath = p.Path, secretValue = p.Value, type = "shared", skipMultilineEncoding = true });
                string hash; try { hash = ValidationPermissionContract.RawHash(bytes); } finally { CryptographicOperations.ZeroMemory(bytes); }
                var write = p.Update ? await c.UpdateValueAsync(target, value, receipt, deadline.Token) : await c.CreateAsync(target, value, receipt, deadline.Token);
                var read = await observer.ReadAsync(new(observer.Authority, address), deadline.Token); string? actual = null, version = null;
                if (read.IsSuccess) { using var material = read.Value; actual = ValidationPermissionContract.Hash(material.Material.Reveal()); version = material.Observation.Version; }
                result.Add(new(p, hash, write.Status, receipt, receipt.Evidence, write.IsSuccess ? write.Value.Version : null, read.Status, actual, version));
            }
            return result.ToArray();
        }
        async Task<ValidationPermissionReceipt> Send<T>(ManagementRequest<T> request, bool setup = false) where T : notnull
        {
            using (request)
            {
                var c = env.CreateManagementClient(); var receipt = c.CreateReceipt(request); var role = setup ? NativeIdentityRole.Setup : boundary == "denied-authority" ? NativeIdentityRole.Denied : NativeIdentityRole.Administrative;
                var barrier = !setup && boundary == "cancellation-boundary" ? new ProjectTokenBarrier(env.Tokens(role)) : null;
                using var cancel = CancellationTokenSource.CreateLinkedTokenSource(deadline.Token);
                using var loss = !setup && boundary == "lost-response-no-replay" ? new ProjectResponseBoundary(env.Origin, cancel) : null; using var scope = loss?.Enter(); Task? entered = barrier?.Entered;
                var auth = new ManagementAuthority(c.Authority, barrier ?? env.Tokens(role), root.Organization, request.Target.ProjectId);
                var execution = c.ExecuteAsync(request, auth, auth.IssueGrant(request.OperationId, request.Target), receipt, cancel.Token).AsTask(); SecretOutcome<T>? result = null; bool cancelled = false;
                try
                {
                    if (entered is not null) { await entered.WaitAsync(deadline.Token); cancel.Cancel(); barrier!.Release(); }
                    try { result = await execution; } catch (OperationCanceledException) when (cancel.IsCancellationRequested && !deadline.IsCancellationRequested) { cancelled = true; }
                    await Assert.That(loss is null || loss.Reached).IsTrue(); return new(receipt, result?.Status, cancelled, request.Target.SecondaryId ?? "");
                }
                finally { cancel.Cancel(); barrier?.Release(); try { result ??= await execution; } catch (OperationCanceledException) { } if (result is { IsSuccess: true } r && r.Value is IDisposable d) d.Dispose(); }
            }
        }
    }
}
