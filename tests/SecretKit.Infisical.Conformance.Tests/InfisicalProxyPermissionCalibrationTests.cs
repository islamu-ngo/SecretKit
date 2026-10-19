using SecretKit.Core;
using SecretKit.Infisical.Management;
using SecretKit.TestFixtures;

namespace SecretKit.Infisical.Conformance.Tests;

// Independent direct SDK/source calibration: no Effects, Client or Trial calls.
public sealed class InfisicalProxyPermissionCalibrationTests
{
    public static IEnumerable<(string Operation, string Variant, string Boundary)> Cases() => InfisicalProxyPermissionOriginalTests.Cases();
    [Test]
    [MethodDataSource(nameof(Cases))]
    public Task DirectSdkCalibratesPersistedProxyPolicyAndDownstreamCrud(string operation, string variant, string boundary) => Calibrate(operation, variant, boundary);
    public static IEnumerable<(string Operation, string Boundary, int Action)> GenericCases() => InfisicalProxyPermissionOriginalTests.SupportedGenericCases();
    [Test]
    [MethodDataSource(nameof(GenericCases))]
    public async Task IndependentGenericCalibrationRetainsOriginalFactory(string operation, string boundary, int action)
    {
        await Assert.That(InfisicalGovernanceFamilies.Bindings[InfisicalProxyPermissionGateTests.Execute].Variants.Contains("factory." + operation)).IsTrue();
        await Calibrate(operation, ProxyPermissionContract.Variant((ProxyPermissionAction)action), boundary);
    }
    private static async Task Calibrate(string operation, string variant, string boundary)
    {
        var action = InfisicalProxyPermissionGateTests.Action(variant);
        await using var provider = new InfisicalProxyPermissionFixture(); using var env = provider.Environment(operation, action);
        using var deadline = new CancellationTokenSource(TimeSpan.FromSeconds(45)); using var cap = SecretMaterial.FromText("proxy-capability");
        var root = provider.Root(operation, action, boundary); var plan = new ProxyPermissionPlan(root); var source = provider.Source.CreateClient();
        using var verifier = new ProxyPermissionVerifier(root); var ownership = new ProxyPermissionOwnership(root, plan);
        ProxyPermissionIssued? issued = null;
        bool template = operation.Contains("ProjectTemplate", StringComparison.Ordinal),
            privilege = operation.Contains("IdentityPrivilegeChange", StringComparison.Ordinal), create = operation.Split('.').Last().StartsWith("Create", StringComparison.Ordinal),
            applied = boundary is not ("denied-authority" or "cancellation-boundary");
        var expected = new Dictionary<string, ProxyPermissionState>();
        try
        {
            Check(await source.StepAsync(root, ProxyPermissionStep.Reserve, cap, deadline.Token), ProxyPermissionStep.Reserve);
            await Assert.That(provider.Generated).IsEqualTo(0);
            var opened = await source.StepAsync(root, ProxyPermissionStep.Open, null, deadline.Token);
            issued = new(opened.Owner.Payload.Content.Actors, opened.Storage.Payload.Content.Bindings); Check(opened, ProxyPermissionStep.Open);
            foreach (var state in opened.Storage.Payload.Content.Inventory)
            {
                ValidateState(state); expected.Add(state.Row, state);
            }
            await Witness(false);
            Check(await source.StepAsync(root, ProxyPermissionStep.Arm, null, deadline.Token), ProxyPermissionStep.Arm);
            ProxyPermissionReceipt original;
            var selected = Enum.Parse<ProjectRoleAction>(action.ToString());
            if (template)
            {
                var config = new ProjectTemplateConfiguration(
                    [new(plan.Slug, plan.Slug, [new(ProjectRoleSubject.ProxiedServices, selected, conditions: [new(RoleConditionField.Environment, ProjectTemplateStringClause.Literal("witness")), new(RoleConditionField.SecretPath, ProjectTemplateStringClause.Literal("/closed"))])])],
                    ProjectTemplateCollection<ProjectTemplateEnvironment>.FromValues([new("Witness", "witness", 1.5)]),
                    users: ProjectTemplateCollection<ProjectTemplateUser>.FromValues([new(plan.Username(plan.ActorKey(0)), [plan.Slug])]));
                original = await Original(create ? ProjectTemplateOperations.CreateProjectTemplate(root.Organization, plan.Slug, configuration: config) :
                    ProjectTemplateOperations.UpdateProjectTemplate(root.Organization, issued.Id(plan.PolicyKey), configuration: config));
            }
            else
            {
                ProjectRolePermission[] permissions = [new(ProjectRoleSubject.ProxiedServices, selected, conditions: [new(RoleConditionField.Environment, RoleStringClause.Literal("witness")), new(RoleConditionField.SecretPath, RoleStringClause.Literal("/closed"))])];
                if (privilege)
                {
                    await Assert.That(issued.Actors[0].Principal).IsEqualTo(InfisicalProxyPermissionFixture.Authorities.Runtime);
                    await Assert.That(issued.Actors[0].Kind).IsEqualTo(MemberPermissionActorKind.Machine);
                    var selection = new LegacyPrivilegeSelection(root.Organization, issued.Id(ProxyPermissionPlan.Project), plan.ProjectSlug,
                        issued.Actors[0].Principal, issued.Id(plan.ActorMembership(0)));
                    var change = new ProjectPrivilegeChange(permissions, PrivilegeLifetime.Permanent(), plan.Slug);
                    original = await Original(create ? IdentityPrivilegeChangeOperations.CreateProjectPrivilege(selection, change) :
                        IdentityPrivilegeChangeOperations.UpdateProjectPrivilege(selection, issued.Id(plan.PolicyKey), change));
                }
                else
                {
                    var change = new ProjectRoleChange(plan.Slug, plan.Slug, permissions: permissions);
                    original = await Original(create ? RoleChangeOperations.CreateProjectRole(root.Organization, issued.Id(ProxyPermissionPlan.Project), change) :
                        RoleChangeOperations.UpdateProjectRole(root.Organization, issued.Id(ProxyPermissionPlan.Project), issued.Id(plan.PolicyKey), change));
                }
            }
            var settled = await source.StepAsync(root, ProxyPermissionStep.Settle, null, deadline.Token); Check(settled, ProxyPermissionStep.Settle);
            await Assert.That(settled.Ingress.Payload.Content.Window.Length).IsEqualTo(boundary == "cancellation-boundary" ? 0 : 1);
            await Assert.That(settled.Policy.Payload.Content.Commits.Length).IsEqualTo(applied ? 1 : 0);
            if (applied)
            {
                var persisted = settled.Policy.Payload.Content.Commits.Single();
                await Assert.That(persisted.Request).IsEqualTo(settled.Ingress.Payload.Content.Window.Single().Request);
                await Assert.That(persisted.Policy.Actor).IsEqualTo(issued.Actors[0].Principal);
                await Assert.That(persisted.Policy.Kind).IsEqualTo(privilege ? MemberPermissionActorKind.Machine : MemberPermissionActorKind.User);
                await Assert.That(persisted.Policy.Subject).IsEqualTo("proxied-services");
                await Assert.That(persisted.Policy.Actions.SequenceEqual([ProxyPermissionContract.Wire(action)])).IsTrue();
                await Assert.That(persisted.Policy.Names.SequenceEqual(["witness", "/closed"])).IsTrue(); await Assert.That(persisted.Policy.Role).IsEqualTo(plan.Slug);
                await Assert.That(persisted.Policy.Resource).IsEqualTo(issued.Id(plan.PolicyKey));
                await Assert.That(persisted.Policy.Organization).IsEqualTo(root.Organization);
                await Assert.That(persisted.Policy.Project).IsEqualTo(issued.Id(ProxyPermissionPlan.Project));
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
                _ = await Original(ProjectMembershipOperations.UpdateProjectMembershipRoles(root.Organization, issued.Id(ProxyPermissionPlan.Project),
                    issued.Id(plan.ActorMembership(0)), [new(plan.Slug)]), true);
            }
            var retainedEvidence = original.Native.Evidence; await Witness(true);
            await Assert.That(original.Native.Evidence).IsEqualTo(retainedEvidence);
            await Assert.That(provider.Originals).IsEqualTo(boundary == "cancellation-boundary" ? 0 : 1);
        }
        finally
        {
            try { Check(await source.StepAsync(root, ProxyPermissionStep.Close, null, CancellationToken.None), ProxyPermissionStep.Close); }
            finally { issued?.Erase(); }
        }
        await InfisicalProxyPermissionEffectTests.Clean(provider);
        void Check(ProxyPermissionPacket packet, ProxyPermissionStep step)
        {
            verifier.Check(packet, step); ownership.Check(packet, step);
            if (issued is not null) issued = issued with { Bindings = packet.Storage.Payload.Content.Bindings };
        }
        async Task<ProxyPermissionReceipt> Original<T>(ManagementRequest<T> request, bool setup = false) where T : notnull
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
        void ValidateState(ProxyPermissionState state)
        {
            var row = plan.Rows.Single(r => r.Key == state.Row); int version = state.Version;
            ProxyPermissionContract.Require(state.Target == issued!.Id(row.Target) && state.Project == issued.Id(row.Project) && state.Organization == root.Organization &&
                state.Name == row.Name + (version == 2 ? "-v2" : "") && state.Host == "api-v" + version + ".example.invalid" &&
                state.Environment == row.Environment && state.SecretPath == row.SecretPath && state.Folder == issued.Id(row.Folder) && state.Enabled == (version == 1), "effect-mismatch");
            foreach (var c in state.Credentials)
                ProxyPermissionContract.Require(c.ServiceId == state.Target && Guid.TryParse(c.Id, out _) && c.Fingerprint == Fingerprint(row, version, c.Slot), "effect-mismatch");
        }
        string Marker(ProxyPermissionRow row, int version, int slot) => ProxyPermissionContract.Hash(new { root.Id, root.Nonce, row.Key, version, slot });
        string Fingerprint(ProxyPermissionRow row, int version, int slot) => ProxyPermissionContract.Hash(new
        {
            Role = "credential-substitution",
            SecretKey = "TARGET_" + slot + "_V" + version,
            PlaceholderKey = "TOKEN_" + slot,
            PlaceholderHash = ProxyPermissionContract.Hash(Marker(row, version, slot)),
            Surfaces = "header,query",
            DynamicSecretName = (string?)null,
            DynamicSecretField = (string?)null,
            HeaderName = (string?)null,
            HeaderPrefix = (string?)null,
            HeaderPurpose = (string?)null
        });
        ProxyPermissionState Snapshot(ProxyPermissionRow row, ProxiedServiceSummary summary, int version)
        {
            ProxyPermissionContract.Require(summary.Credentials.Count == 2 && summary.HasIsEnabled, "effect-mismatch");
            ProxyPermissionCredentialState Credential(int slot)
            {
                var c = summary.Credentials[slot];
                ProxyPermissionContract.Require(c.ServiceId == summary.Id && c.Role == "credential-substitution" &&
                    c.SecretKey == "TARGET_" + slot + "_V" + version && c.PlaceholderKey == "TOKEN_" + slot &&
                    c.PlaceholderValue?.Reveal() == Marker(row, version, slot) && c.SubstitutionSurfaces is not null &&
                    c.SubstitutionSurfaces.SequenceEqual(["header", "query"]) && c.HasDynamicSecretName && c.DynamicSecretName is null &&
                    c.HasDynamicSecretField && c.DynamicSecretField is null && c.HasHeaderName && c.HeaderName is null &&
                    c.HasHeaderPrefix && c.HeaderPrefix is null && c.HasHeaderPurpose && c.HeaderPurpose is null, "effect-mismatch");
                return new(slot, c.Id, c.ServiceId, Fingerprint(row, version, slot));
            }
            return new(row.Key, summary.Id, issued!.Id(row.Organization), issued.Id(row.Project), summary.Name, summary.HostPattern,
                row.Environment, row.SecretPath, summary.FolderId, summary.IsEnabled!.Value, version, Credential(0), Credential(1));
        }
        async Task Witness(bool after)
        {
            var step = after ? ProxyPermissionStep.After : ProxyPermissionStep.Before;
            var beginning = await source.StepAsync(root, step, null, deadline.Token); Check(beginning, step);
            if (after && template && applied)
            {
                foreach (var state in beginning.Storage.Payload.Content.Inventory.Where(s => plan.Rows.Any(r => r.Key == s.Row && r.Window == "copy")))
                { ValidateState(state); expected.Add(state.Row, state); }
                var config = beginning.Storage.Payload.Content.Templates.Single();
                await Assert.That(config.Environment).IsEqualTo("witness"); await Assert.That(config.Position).IsEqualTo(1.5);
            }
            var rows = plan.Rows.Where(r => r.Window == (!after ? "before" : template && applied ? "copy" : "after")).ToArray();
            var returned = new Dictionary<string, ProxyPermissionState?>(); var submitted = new Dictionary<string, string>(); var paths = new Dictionary<string, string>();
            foreach (var row in rows)
            {
                var actor = issued!.Actors[row.Actor]; string organization = issued.Id(row.Organization), project = issued.Id(row.Project), target = issued.Id(row.Target);
                using var tokens = actor.Owned ? new MemberPermissionTokens(actor.Credential) : new MemberPermissionTokens(env.Tokens(
                    actor.Principal == root.Authorities.Runtime ? NativeIdentityRole.Runtime : NativeIdentityRole.Denied));
                int version = row.Action == ProxyPermissionAction.Edit ? 2 : 1;
                using var m0 = SecretMaterial.FromText(Marker(row, version, 0)); using var m1 = SecretMaterial.FromText(Marker(row, version, 1));
                using var c0 = new ProxiedServiceCredentialInput(ProxiedServiceCredentialRole.CredentialSubstitution, secretKey: "TARGET_0_V" + version,
                    placeholderKey: "TOKEN_0", placeholderValue: m0, substitutionSurfaces: [ProxiedServiceSubstitutionSurface.Header, ProxiedServiceSubstitutionSurface.Query]);
                using var c1 = new ProxiedServiceCredentialInput(ProxiedServiceCredentialRole.CredentialSubstitution, secretKey: "TARGET_1_V" + version,
                    placeholderKey: "TOKEN_1", placeholderValue: m1, substitutionSurfaces: [ProxiedServiceSubstitutionSurface.Header, ProxiedServiceSubstitutionSurface.Query]);
                using var creation = new ProxiedServiceCreation(project, row.Environment, row.Name, "api-v1.example.invalid", [c0, c1], row.SecretPath, true);
                using var update = new ProxiedServiceUpdate(row.Name + "-v2", "api-v2.example.invalid", false, [c0, c1]);
                using var request = row.Action switch
                {
                    ProxyPermissionAction.Read => ProxiedServiceAdministrationOperations.Get(organization, project, target),
                    ProxyPermissionAction.Create => ProxiedServiceAdministrationOperations.Create(organization, creation),
                    ProxyPermissionAction.Edit => ProxiedServiceAdministrationOperations.Update(organization, project, target, update),
                    ProxyPermissionAction.Delete => ProxiedServiceAdministrationOperations.Delete(organization, project, target),
                    _ => throw new InvalidOperationException()
                };
                submitted.Add(row.Key, row.Action is ProxyPermissionAction.Create or ProxyPermissionAction.Edit ? request.Target.SecondaryId! : ProxyPermissionContract.RawHash([]));
                paths.Add(row.Key, "/api/v1/proxied-services" + (row.Action == ProxyPermissionAction.Create ? "" : "/" + target));
                bool allowed = row.Control == "selected" && (after && applied ? row.Action == action : !create && (int)row.Action == ((int)action + 1) % 4);
                var client = env.CreateManagementClient(); var authority = new ManagementAuthority(client.Authority, tokens, organization, project);
                var receipt = request.IsMutation ? client.CreateReceipt(request) : null;
                var result = await client.ExecuteAsync(request, authority, authority.IssueGrant(request.OperationId, request.Target), receipt, deadline.Token);
                await Assert.That(result.Status).IsEqualTo(allowed ? SecretStatus.Success : SecretStatus.Denied);
                await Assert.That(tokens.Hash).IsEqualTo(actor.CredentialHash);
                if (receipt is not null) await Assert.That(receipt.Evidence).IsEqualTo(allowed ? DispatchEvidence.Applied : DispatchEvidence.Rejected);
                if (result.IsSuccess)
                {
                    using var summary = result.Value;
                    if (row.Action == ProxyPermissionAction.Delete)
                    {
                        await Assert.That(summary.Id).IsEqualTo(target); await Assert.That(summary.Name).IsEqualTo(row.Name);
                        await Assert.That(summary.HasCredentials).IsFalse(); returned.Add(row.Key, null);
                    }
                    else returned.Add(row.Key, Snapshot(row, summary, version));
                }
            }
            var end = after ? ProxyPermissionStep.ObserveAfter : ProxyPermissionStep.ObserveBefore;
            var packet = await source.StepAsync(root, end, null, deadline.Token); Check(packet, end);
            await Assert.That(packet.Access.Payload.Content.Length).IsEqualTo(rows.Length);
            var join = packet.Membership.Payload.Content.Single(j => j.Membership == issued!.Id(plan.ActorMembership(0, after && template && applied)));
            bool active = !create || after && applied;
            await Assert.That(join.Assigned).IsEqualTo(active); await Assert.That(join.RoleSlug).IsEqualTo(active ? plan.Slug : "no-access");
            for (int index = 0; index < rows.Length; index++)
            {
                var row = rows[index]; var decision = packet.Access.Payload.Content[index]; var actor = issued!.Actors[row.Actor];
                await Assert.That(decision.Target).IsEqualTo(issued.Id(row.Target)); await Assert.That(decision.Action).IsEqualTo(row.Action);
                await Assert.That(decision.Actor).IsEqualTo(actor.Principal); await Assert.That(decision.Kind).IsEqualTo(actor.Kind);
                await Assert.That(decision.CredentialHash).IsEqualTo(actor.CredentialHash); await Assert.That(decision.Organization).IsEqualTo(issued.Id(row.Organization));
                await Assert.That(decision.Project).IsEqualTo(issued.Id(row.Project));
                var ingress = packet.Ingress.Payload.Content.Window.Single(e => e.Request == decision.Request);
                await Assert.That(ingress.BodyHash).IsEqualTo(submitted[row.Key]); await Assert.That(ingress.Path).IsEqualTo(paths[row.Key]);
                await Assert.That(packet.Issuer.Payload.Content.Credentials.Any(c => c.Id == decision.CredentialId && c.Principal == decision.Actor && c.Kind == decision.Kind && c.Hash == decision.CredentialHash)).IsTrue();
                var before = expected.GetValueOrDefault(row.Key); var next = returned.TryGetValue(row.Key, out var value) ? value : before;
                if (next is not null) ValidateState(next);
                await Assert.That(packet.Storage.Payload.Content.Changes.Single(c => c.Request == decision.Request)).IsEqualTo(new ProxyPermissionChange(decision.Request, row.Key, before, next));
                if (next is null) expected.Remove(row.Key); else expected[row.Key] = next;
            }
            await Assert.That(packet.Storage.Payload.Content.Inventory.OrderBy(s => s.Row).SequenceEqual(expected.Values.OrderBy(s => s.Row))).IsTrue();
            foreach (var scope in plan.Rows.Select(r => (Project: issued!.Id(r.Project), r.Environment, r.SecretPath)).Where(s => s.Project.Length > 0).Distinct())
            {
                var client = env.CreateManagementClient(); var authority = new ManagementAuthority(client.Authority, env.Tokens(NativeIdentityRole.Observer), root.Organization, scope.Project);
                using var list = ProxiedServiceAdministrationOperations.List(root.Organization, scope.Project, scope.Environment, scope.SecretPath);
                var result = await client.ExecuteAsync(list, authority, authority.IssueGrant(list.OperationId, list.Target), cancellationToken: deadline.Token);
                await Assert.That(result.IsSuccess).IsTrue(); using var inventory = result.Value;
                var selected = expected.Values.Where(s => s.Project == scope.Project && s.Environment == scope.Environment && s.SecretPath == scope.SecretPath).ToArray();
                await Assert.That(inventory.Services.Select(s => s.Id).Order().SequenceEqual(selected.Select(s => s.Target).Order())).IsTrue();
                foreach (var state in selected)
                {
                    var row = plan.Rows.Single(r => r.Key == state.Row);
                    await Assert.That(Snapshot(row, inventory.Services.Single(s => s.Id == state.Target), state.Version)).IsEqualTo(state);
                    using var get = ProxiedServiceAdministrationOperations.Get(root.Organization, state.Project, state.Target);
                    var fetched = await client.ExecuteAsync(get, authority, authority.IssueGrant(get.OperationId, get.Target), cancellationToken: deadline.Token);
                    await Assert.That(fetched.IsSuccess).IsTrue(); using var summary = fetched.Value;
                    await Assert.That(Snapshot(row, summary, state.Version)).IsEqualTo(state);
                    using var named = ProxiedServiceAdministrationOperations.GetByName(root.Organization, state.Project, state.Environment, state.Name, state.SecretPath);
                    var found = await client.ExecuteAsync(named, authority, authority.IssueGrant(named.OperationId, named.Target), cancellationToken: deadline.Token);
                    await Assert.That(found.IsSuccess).IsTrue(); using var byName = found.Value;
                    await Assert.That(Snapshot(row, byName, state.Version)).IsEqualTo(state);
                }
            }
        }
    }
}
